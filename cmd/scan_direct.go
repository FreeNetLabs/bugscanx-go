package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/Ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var scanDirectCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection",
	Run:   scanDirectRun,
}

var (
	scanDirectFlagFilename string
	scanDirectFlagHttps    bool
	scanDirectFlagTimeout  int
	scanDirectFlagOutput   string
	scanDirectFlagMethod   string
	scanDirectFlagShow302  bool
)

func init() {
	rootCmd.AddCommand(scanDirectCmd)

	scanDirectCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	scanDirectCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	scanDirectCmd.Flags().IntVar(&scanDirectFlagTimeout, "timeout", 3, "connect timeout")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "http method")
	scanDirectCmd.Flags().BoolVar(&scanDirectFlagShow302, "show302", false, "show 302 status code results")

	scanDirectCmd.MarkFlagFilename("filename")
	scanDirectCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain string
	Scheme string
	Method string
}

type scanDirectResponse struct {
	Color      *color.Color
	Request    *scanDirectRequest
	NetIPList  []net.IP
	StatusCode int
	Server     string
}

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
	Timeout: 5 * time.Second,
}

var ctxBackground = context.Background()

var serverColors = map[string]*color.Color{
	"cloudflare": colorG1,
	"akamai":     colorY1,
	"cloudfront": colorC1,
	"awselb":     colorC1,
	"amazons3":   colorC1,
	"varnish":    colorM1,
	"fastly":     colorM1,
	"microsoft":  colorC2,
	"azure":      colorC2,
	"cachefly":   colorY2,
	"alibaba":    colorY2,
	"tencent":    colorM2,
}

func getServerColor(server string) *color.Color {
	serverLower := strings.ToLower(server)
	for k, v := range serverColors {
		if strings.Contains(serverLower, k) {
			return v
		}
	}
	return colorB1
}

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	ctxTimeout, cancel := context.WithTimeout(ctxBackground, 3*time.Second)
	defer cancel()
	netIPList, err := net.DefaultResolver.LookupIP(ctxTimeout, "ip4", req.Domain)
	if err != nil {
		return
	}
	ip := netIPList[0].String()

	httpReq, err := http.NewRequest(req.Method, fmt.Sprintf("%s://%s", req.Scheme, req.Domain), nil)
	if err != nil {
		return
	}

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return
	}

	if httpRes.StatusCode == 302 && !scanDirectFlagShow302 {
		return
	}

	hServer := httpRes.Header.Get("Server")
	resColor := getServerColor(hServer)

	res := &scanDirectResponse{
		Color:      resColor,
		Request:    req,
		NetIPList:  netIPList,
		StatusCode: httpRes.StatusCode,
		Server:     hServer,
	}
	c.ScanSuccess(res, nil)

	s := fmt.Sprintf(
		"%-15s  %-4d  %-16s  %s",
		ip,
		httpRes.StatusCode,
		hServer,
		req.Domain,
	)

	s = resColor.Sprint(s)
	c.Log(s)
}

func printHeaders() {
	fmt.Println()
	colorC1.Printf("%-15s  ", "IP")
	colorY1.Printf("%-4s  ", "CODE")
	colorM1.Printf("%-16s  ", "SERVER")
	colorG1.Printf("%-s\n", "HOST")
	colorW1.Printf("%-15s  %-4s  %-16s  %-s\n", "---", "----", "------", "----")
	fmt.Println()
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	domainList := make(map[string]bool)

	domainListFile, err := os.Open(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		domainList[domain] = true
	}

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	printHeaders()

	scheme := "http"
	if scanDirectFlagHttps {
		scheme = "https"
	}

	for domain := range domainList {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s://%s", scheme, domain),
			Data: &scanDirectRequest{
				Domain: domain,
				Scheme: scheme,
				Method: scanDirectFlagMethod,
			},
		})
	}
	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		c.Log("")

		mapServerList := make(map[string][]*scanDirectResponse)

		for _, data := range c.ScanSuccessList {
			res, ok := data.(*scanDirectResponse)
			if !ok {
				continue
			}

			mapServerList[res.Server] = append(mapServerList[res.Server], res)
		}

		domainList := make([]string, 0)
		ipList := make([]string, 0)

		for server, resList := range mapServerList {
			if len(resList) == 0 {
				continue
			}

			var resColor *color.Color

			mapIPList := make(map[string]bool)
			mapDomainList := make(map[string]bool)

			for _, res := range resList {
				if resColor == nil {
					resColor = res.Color
				}

				for _, netIP := range res.NetIPList {
					ip := netIP.String()
					mapIPList[ip] = true
				}

				mapDomainList[res.Request.Domain] = true
			}

			c.Log(resColor.Sprintf("\n%s\n", server))

			domainList = append(domainList, fmt.Sprintf("# %s", server))
			for doamin := range mapDomainList {
				domainList = append(domainList, doamin)
				c.Log(resColor.Sprint(doamin))
			}
			domainList = append(domainList, "")
			c.Log("")

			ipList = append(ipList, fmt.Sprintf("# %s", server))
			for ip := range mapIPList {
				ipList = append(ipList, ip)
				c.Log(resColor.Sprint(ip))
			}
			ipList = append(ipList, "")
			c.Log("")
		}

		outputList := make([]string, 0)
		outputList = append(outputList, domainList...)
		outputList = append(outputList, ipList...)

		if scanDirectFlagOutput != "" {
			err := os.WriteFile(scanDirectFlagOutput, []byte(strings.Join(outputList, "\n")), 0644)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
