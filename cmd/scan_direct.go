package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var directCmd = &cobra.Command{
	Use:     "direct",
	Short:   "Scan using direct connection to targets.",
	Example: "  bugscanx-go direct -f hosts.txt\n  bugscanx-go direct -f hosts.txt --https --method GET",
	Run:     scanDirectRun,
}

var (
	scanDirectFlagFilename       string
	scanDirectFlagHttps          bool
	scanDirectFlagOutput         string
	scanDirectFlagHideLocation   string
	scanDirectFlagMethod         string
	scanDirectFlagTimeoutConnect int
	scanDirectFlagTimeoutTLS     int
	scanDirectFlagTimeoutHeader  int
	scanDirectFlagTimeoutRequest int
)

func init() {
	rootCmd.AddCommand(directCmd)

	directCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "HTTP method to use (e.g. HEAD, GET, POST)")
	directCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	directCmd.Flags().StringVar(&scanDirectFlagHideLocation, "hide-location", "https://jio.com/BalanceExhaust", "hide results with this Location header")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds (default 5)")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutTLS, "timeout-tls", 2, "TLS handshake timeout in seconds (default 2)")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutHeader, "timeout-header", 3, "Response header timeout in seconds (default 3)")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds (default 10)")

	directCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain string
}

func newHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(scanDirectFlagTimeoutConnect) * time.Second,
				KeepAlive: -1,
			}).DialContext,
			TLSHandshakeTimeout:   time.Duration(scanDirectFlagTimeoutTLS) * time.Second,
			ResponseHeaderTimeout: time.Duration(scanDirectFlagTimeoutHeader) * time.Second,
		},
	}
}

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	httpScheme := "http"
	if scanDirectFlagHttps {
		httpScheme = "https"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scanDirectFlagTimeoutRequest)*time.Second)
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

	client := newHTTPClient()
	httpRes, err := client.Do(httpReq)
	if err != nil {
		return
	}
	defer httpRes.Body.Close()

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

	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ip, httpRes.StatusCode, hServer, req.Domain)
	c.ScanSuccess(formatted)
	c.Log(formatted)
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
	queueScanner.SetOutputFile(scanDirectFlagOutput)
	queueScanner.Start()
}
