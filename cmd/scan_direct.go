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

// directCmd performs direct HTTP/HTTPS connections to target hosts.
var directCmd = &cobra.Command{
	Use:     "direct",
	Short:   "Scan using direct connection to targets.",
	Example: "  bugscanx-go direct -f hosts.txt\n  bugscanx-go direct -f hosts.txt --https --method GET",
	Run:     scanDirectRun,
}

// Direct scan command flags
var (
	scanDirectFlagFilename       string // Input file containing domains to scan
	scanDirectFlagHttps          bool   // Use HTTPS (port 443) instead of HTTP (port 80)
	scanDirectFlagOutput         string // Output file for successful results
	scanDirectFlagHideLocation   string // Filter out responses with this Location header
	scanDirectFlagMethod         string // HTTP method to use (HEAD, GET, POST, etc.)
	scanDirectFlagTimeoutConnect int    // TCP connection timeout in seconds
	scanDirectFlagTimeoutRequest int    // Overall request timeout in seconds
)

// init sets up the direct command with flags and validation.
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

// extractHTTPHeaders extracts status code, server, and location from HTTP response.
func extractHTTPHeaders(response string) (statusCode int, server string, location string) {
	lines := strings.Split(response, "\n")

	// Parse status line to extract HTTP status code
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				statusCode = code
			}
		}
	}

	// Parse headers to extract Server and Location values
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

// scanDirect performs a direct HTTP/HTTPS scan on a target domain.
func scanDirect(c *queuescanner.Ctx, domain string) {
	// Determine port based on protocol
	port := "80"
	if scanDirectFlagHttps {
		port = "443"
	}

	// Resolve IP addresses
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", domain)
	if err != nil || len(ips) == 0 {
		return
	}

	// Use the first resolved IPv4 address
	ip := ips[0]
	ipStr := ip.String()
	address := fmt.Sprintf("%s:%s", ipStr, port)
	network := "tcp4"

	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(scanDirectFlagTimeoutConnect) * time.Second,
	}

	// Establish connection
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

	// Set overall timeout for the request
	conn.SetDeadline(time.Now().Add(time.Duration(scanDirectFlagTimeoutRequest) * time.Second))

	// Determine HTTP method
	method := scanDirectFlagMethod
	if method == "" {
		method = "HEAD"
	}

	// Craft HTTP request with proper headers
	httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, domain)

	// Send HTTP request
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return
	}

	// Read response with buffer
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	// Parse HTTP response
	response := string(buffer[:n])
	statusCode, server, location := extractHTTPHeaders(response)

	// Filter results based on Location header if configured
	if scanDirectFlagHideLocation != "" && location == scanDirectFlagHideLocation {
		return
	}

	// Format successful scan result
	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ipStr, statusCode, server, domain)

	// Log successful result
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

// scanDirectRun orchestrates the direct scanning process.
func scanDirectRun(cmd *cobra.Command, args []string) {
	// Read target domains from input file
	hosts, err := ReadLines(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Print table headers for results
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	// Initialize queue scanner with configured thread count
	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)

	// Add all domains to the scan queue
	queueScanner.Add(hosts)

	// Configure output file if specified
	queueScanner.SetOutputFile(scanDirectFlagOutput)

	// Start the scanning process
	queueScanner.Start()
}
