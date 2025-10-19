package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var directCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection to targets.",
	Run:   scanDirectRun,
}

var (
	directFlagFilename       string
	directFlagPort           string
	directFlagOutput         string
	directFlagHideLocation   string
	directFlagMethod         string
	directFlagTimeoutConnect int
	directFlagTimeoutRequest int
)

func init() {
	rootCmd.AddCommand(directCmd)

	directCmd.Flags().StringVarP(&directFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&directFlagPort, "port", "p", "80", "port to scan (default: 80)")
	directCmd.Flags().StringVarP(&directFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&directFlagMethod, "method", "m", "HEAD", "HTTP method to use")
	directCmd.Flags().StringVar(&directFlagHideLocation, "skip", "https://jio.com/BalanceExhaust", "skip results with this Location header")
	directCmd.Flags().IntVar(&directFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds")
	directCmd.Flags().IntVar(&directFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds")

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

func scanDirect(c *queuescanner.Ctx, host string) {
	port := directFlagPort
	if port == "" {
		port = "80"
	}

	// Determine if we should use TLS based on common HTTPS ports
	useTLS := false
	commonHTTPSPorts := []string{"443", "8443", "9443", "10443"}
	for _, httpsPort := range commonHTTPSPorts {
		if port == httpsPort {
			useTLS = true
			break
		}
	}

	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return
	}

	ip := ips[0]
	ipStr := ip.String()
	address := fmt.Sprintf("%s:%s", ipStr, port)
	network := "tcp4"

	dialer := &net.Dialer{
		Timeout: time.Duration(directFlagTimeoutConnect) * time.Second,
	}

	var conn net.Conn
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, network, address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
	} else {
		conn, err = dialer.Dial(network, address)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(directFlagTimeoutRequest) * time.Second))

	method := directFlagMethod
	if method == "" {
		method = "HEAD"
	}

	httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, host)

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

	if directFlagHideLocation != "" && location == directFlagHideLocation {
		return
	}

	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ipStr, statusCode, server, host)

	c.ScanSuccess(formatted)
	c.Log(formatted)
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	hosts, err := ReadFile(directFlagFilename)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	queueScanner.Add(hosts)
	queueScanner.SetOutputFile(directFlagOutput)
	queueScanner.SetPrintInterval(globalFlagPrintInterval)
	queueScanner.Start()
}
