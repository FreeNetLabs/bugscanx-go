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

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var directCmd = &cobra.Command{
	Use:     "direct",
	Short:   "Scan using direct connection to targets.",
	Long:    "Scan a list of hosts using direct HTTP(S) connections. Supports custom HTTP methods, HTTPS, and filtering by Location header.",
	Example: "  bugscanx-go direct -f hosts.txt\n  bugscanx-go direct -f hosts.txt --https --method GET",
	Run:     scanDirectRun,
}

var (
	scanDirectFlagFilename     string
	scanDirectFlagHttps        bool
	scanDirectFlagOutput       string
	scanDirectFlagHideLocation string
	scanDirectFlagMethod       string
)

func init() {
	rootCmd.AddCommand(directCmd)

	directCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "HTTP method to use (e.g. HEAD, GET, POST)")
	directCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	directCmd.Flags().StringVar(&scanDirectFlagHideLocation, "hide-location", "https://jio.com/BalanceExhaust", "hide results with this Location header")

	directCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain string
}

type scanDirectResponse struct {
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
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	},
}

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	httpScheme := "http"
	if scanDirectFlagHttps {
		httpScheme = "https"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	method := scanDirectFlagMethod
	if method == "" {
		method = "HEAD"
	}

	httpReq, err := http.NewRequest(method, fmt.Sprintf("%s://%s", httpScheme, req.Domain), nil)
	if err != nil {
		return
	}

	httpReq = httpReq.WithContext(ctx)

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return
	}
	hServer := httpRes.Header.Get("Server")
	hLocation := httpRes.Header.Get("Location")

	if scanDirectFlagHideLocation != "" && hLocation == scanDirectFlagHideLocation {
		return
	}

	netIPs, _ := net.LookupIP(req.Domain)
	ip := "unknown"
	if len(netIPs) > 0 {
		ip = netIPs[0].String()
	}

	res := &scanDirectResponse{
		Request:    req,
		NetIPList:  netIPs,
		StatusCode: httpRes.StatusCode,
		Server:     hServer,
		Location:   hLocation,
	}
	c.ScanSuccess(res, nil)

	c.Logf("%-15s  %-3d   %-16s    %s", ip, httpRes.StatusCode, hServer, req.Domain)
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

	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	for domain := range domainList {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: &scanDirectRequest{
				Domain: domain,
			},
		})
	}
	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		if scanDirectFlagOutput != "" {
			outputList := make([]string, 0)
			for _, data := range c.ScanSuccessList {
				res, ok := data.(*scanDirectResponse)
				if !ok {
					continue
				}
				outputList = append(outputList, res.Request.Domain)
			}

			err := os.WriteFile(scanDirectFlagOutput, []byte(strings.Join(outputList, "\n")), 0644)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
