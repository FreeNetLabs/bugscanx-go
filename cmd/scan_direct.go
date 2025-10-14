package cmd

import (
	"context"
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
	Run:     scanDirectRun,
}

var (
	scanDirectFlagFilename       string
	scanDirectFlagHttps          bool
	scanDirectFlagOutput         string
	scanDirectFlagHideLocation   string
	scanDirectFlagMethod         string
	scanDirectFlagTimeoutConnect int
	scanDirectFlagTimeoutRequest int
)

func init() {
	rootCmd.AddCommand(directCmd)

	directCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "HTTP method to use")
	directCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	directCmd.Flags().StringVar(&scanDirectFlagHideLocation, "skip", "https://jio.com/BalanceExhaust", "skip results with this Location header")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds")

	directCmd.MarkFlagRequired("filename")
}

func extractHTTPHeaders(response string) (statusCode int, server string, location string) {
	lines := strings.Split(response, "\n")

	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				statusCode = code
			}
		}
	}

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

func scanDirect(c *queuescanner.Ctx, domain string) {
	port := "80"
	if scanDirectFlagHttps {
		port = "443"
	}

	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", domain)
	if err != nil || len(ips) == 0 {
		return
	}

	ip := ips[0]
	ipStr := ip.String()
	address := fmt.Sprintf("%s:%s", ipStr, port)
	network := "tcp4"

	dialer := &net.Dialer{
		Timeout: time.Duration(scanDirectFlagTimeoutConnect) * time.Second,
	}

	var conn net.Conn
	if scanDirectFlagHttps {
		conn, err = tls.DialWithDialer(dialer, network, address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		})
	} else {
		conn, err = dialer.Dial(network, address)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(scanDirectFlagTimeoutRequest) * time.Second))

	method := scanDirectFlagMethod
	if method == "" {
		method = "HEAD"
	}

	httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, domain)

	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	statusCode, server, location := extractHTTPHeaders(response)

	if scanDirectFlagHideLocation != "" && location == scanDirectFlagHideLocation {
		return
	}

	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ipStr, statusCode, server, domain)

	c.ScanSuccess(formatted)
	c.Log(formatted)
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	hosts, err := ReadLines(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	queueScanner.Add(hosts)
	queueScanner.SetOutputFile(scanDirectFlagOutput)
	queueScanner.Start()
}
