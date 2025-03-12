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

	"github.com/Ayanrajpoot10/bugscanx-go/pkg/queuescanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var scanDirectCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection",
	Run:   scanDirectRun,
}

var (
	scanDirectFlagFilename    string
	scanDirectFlagHttps       bool
	scanDirectFlagTimeout     int
	scanDirectFlagOutput      string
	scanDirectFlagMethod      string
	scanDirectFlagBothSchemes bool
)

func init() {
	scanCmd.AddCommand(scanDirectCmd)

	scanDirectCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	scanDirectCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	scanDirectCmd.Flags().IntVar(&scanDirectFlagTimeout, "timeout", 3, "connect timeout")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	scanDirectCmd.Flags().StringVar(&scanDirectFlagMethod, "method", "HEAD", "HTTP method to use (e.g., GET, POST, etc.)")
	scanDirectCmd.Flags().BoolVar(&scanDirectFlagBothSchemes, "both-schemes", false, "scan both HTTP and HTTPS")

	scanDirectCmd.MarkFlagFilename("filename")
	scanDirectCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain     string
	Https      bool
	ServerList []string
}

type scanDirectResponse struct {
	Color      *color.Color
	Request    *scanDirectRequest
	NetIPList  []net.IP
	StatusCode int
	Server     string
	Location   string
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
	Timeout: 10 * time.Second,
}

var ctxBackground = context.Background()

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	ctxTimeout, cancel := context.WithTimeout(ctxBackground, time.Duration(scanDirectFlagTimeout)*time.Second)
	defer cancel()
	netIPList, err := net.DefaultResolver.LookupIP(ctxTimeout, "ip4", req.Domain)
	if err != nil {
		return
	}
	if len(netIPList) == 0 {
		return
	}
	ip := netIPList[0].String()

	schemes := []string{"http"}
	if req.Https || scanDirectFlagBothSchemes {
		schemes = append(schemes, "https")
	}
	for _, scheme := range schemes {
		method := strings.ToUpper(scanDirectFlagMethod)
		httpReq, err := http.NewRequest(method, fmt.Sprintf("%s://%s", scheme, req.Domain), nil)
		if err != nil {
			continue
		}

		httpRes, err := httpClient.Do(httpReq)
		if err != nil {
			continue
		}

		hServer := httpRes.Header.Get("Server")
		hServerLower := strings.ToLower(hServer)
		hLocation := httpRes.Header.Get("Location")

		if strings.Contains(hLocation, "BalanceExhaust") {
			return
		}

		var resColor *color.Color

		serverColors := map[string]*color.Color{
			"cloudflare":   colorG1,
			"akamaighost":  colorY1,
			"akamai":       colorY1,
			"cloudfront":   colorC1,
			"amazons3":     colorC1,
			"varnish":      colorM1,
			"fastly":       colorM1,
			"microsoft":    colorC2,
			"azure":        colorC2,
			"cachefly":     colorY2,
			"alibaba":      colorY2,
			"tencent":      colorM2,
		}

		if color, exists := serverColors[hServerLower]; exists {
			resColor = color
		} else {
			resColor = colorB1
		}

		res := &scanDirectResponse{
			Color:      resColor,
			Request:    req,
			NetIPList:  netIPList,
			StatusCode: httpRes.StatusCode,
			Server:     hServer,
		}
		c.ScanSuccess(res, nil)

		s := fmt.Sprintf(
			"%-15s  %-3d  %-16s    %s",
			ip,
			httpRes.StatusCode,
			hServer,
			req.Domain,
		)

		s = resColor.Sprint(s)

		c.Log(s)
	}
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	domainListFile, err := os.Open(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	queueScanner := queuescanner.NewQueueScanner(scanFlagThreads, scanDirect)

	colorC1.Printf("\n%-15s  ", "IP")
	colorY1.Printf("%-3s  ", "CODE")
	colorM1.Printf("%-16s    ", "SERVER")
	colorG1.Printf("%-20s\n", "HOST")
	colorW1.Printf("%-15s  %-3s  %-16s    %-20s\n", "----", "----", "------", "----")

	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: &scanDirectRequest{
				Domain:     domain,
				Https:      scanDirectFlagHttps,
			},
		})
	}

	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		if scanDirectFlagOutput != "" {
			outputList := []string{
				"IP             CODE  SERVER            HOST",
				"----           ----  ------            ----",
			}

			for _, data := range c.ScanSuccessList {
				res, ok := data.(*scanDirectResponse)
				if !ok {
					continue
				}
				ip := res.NetIPList[0].String()
				line := fmt.Sprintf("%-15s  %-3d  %-16s    %s", ip, res.StatusCode, res.Server, res.Request.Domain)
				outputList = append(outputList, line)
			}

			outputFile, err := os.Create(scanDirectFlagOutput)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			defer outputFile.Close()

			writer := bufio.NewWriter(outputFile)
			for _, line := range outputList {
				writer.WriteString(line + "\n")
			}
			writer.Flush()

			fmt.Print(colorG1.Sprintf("✅ Results saved to %s\n", scanDirectFlagOutput))
		}
	})
}