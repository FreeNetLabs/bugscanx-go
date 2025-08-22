package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
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
	directCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "HTTP method to use")
	directCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	directCmd.Flags().StringVar(&scanDirectFlagHideLocation, "hide-location", "https://jio.com/BalanceExhaust", "hide results with this Location header")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutTLS, "timeout-tls", 2, "TLS handshake timeout in seconds")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutHeader, "timeout-header", 3, "Response header timeout in seconds")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds")

	directCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain string
}

func dialWithTimeout(network, address string, timeout time.Duration, useTLS bool) (net.Conn, error) {
	if useTLS {
		return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, network, address, &tls.Config{
			InsecureSkipVerify: true,
		})
	}
	return net.DialTimeout(network, address, timeout)
}

func parseHTTPResponse(response string) (statusCode int, server string, location string) {
	lines := strings.Split(response, "\n")

	// Parse status line
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				statusCode = code
			}
		}
	}

	// Parse headers
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[9:])
		}
	}

	return statusCode, server, location
}

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	port := "80"
	if scanDirectFlagHttps {
		port = "443"
	}

	address := fmt.Sprintf("%s:%s", req.Domain, port)

	// Establish connection with timeout
	conn, err := dialWithTimeout("tcp", address, time.Duration(scanDirectFlagTimeoutConnect)*time.Second, scanDirectFlagHttps)
	if err != nil {
		return
	}
	defer conn.Close()

	// Set overall timeout for the request
	conn.SetDeadline(time.Now().Add(time.Duration(scanDirectFlagTimeoutRequest) * time.Second))

	method := scanDirectFlagMethod
	if method == "" {
		method = "HEAD"
	}

	// Craft HTTP request
	httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, req.Domain)

	// Send request
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	statusCode, hServer, hLocation := parseHTTPResponse(response)

	if scanDirectFlagHideLocation != "" && hLocation == scanDirectFlagHideLocation {
		return
	}

	ip := "unknown"
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
			ip = tcpAddr.IP.String()
		}
	}

	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ip, statusCode, hServer, req.Domain)
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	hosts, err := ReadLinesFromFile(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	for _, domain := range hosts {
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
