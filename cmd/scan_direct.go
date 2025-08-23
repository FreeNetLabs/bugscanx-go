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

// directCmd represents the direct scanning command.
// This command performs direct HTTP/HTTPS connections to target hosts
// without using any proxy or intermediary. It's useful for basic web
// service enumeration and connectivity testing.
var directCmd = &cobra.Command{
	Use:     "direct",
	Short:   "Scan using direct connection to targets.",
	Example: "  bugscanx-go direct -f hosts.txt\n  bugscanx-go direct -f hosts.txt --https --method GET",
	Run:     scanDirectRun,
}

// Direct scan command flags
var (
	// scanDirectFlagFilename specifies the input file containing the list of domains to scan
	scanDirectFlagFilename string

	// scanDirectFlagHttps enables HTTPS mode (port 443) instead of HTTP (port 80)
	scanDirectFlagHttps bool

	// scanDirectFlagOutput specifies the output file to save successful scan results
	scanDirectFlagOutput string

	// scanDirectFlagHideLocation filters out responses with a specific Location header value
	scanDirectFlagHideLocation string

	// scanDirectFlagMethod specifies the HTTP method to use for requests (HEAD, GET, POST, etc.)
	scanDirectFlagMethod string

	// scanDirectFlagTimeoutConnect sets the TCP connection timeout in seconds
	scanDirectFlagTimeoutConnect int

	// scanDirectFlagTimeoutRequest sets the overall request timeout in seconds
	scanDirectFlagTimeoutRequest int
)

// init initializes the direct command and its flags.
// This function is automatically called when the package is imported
// and sets up the command configuration, flags, and validation rules.
func init() {
	// Add the direct command to the root command
	rootCmd.AddCommand(directCmd)

	// Define command-specific flags
	directCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&scanDirectFlagMethod, "method", "m", "HEAD", "HTTP method to use")
	directCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	directCmd.Flags().StringVar(&scanDirectFlagHideLocation, "hide-location", "https://jio.com/BalanceExhaust", "hide results with this Location header")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds")
	directCmd.Flags().IntVar(&scanDirectFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds")

	// Mark required flags
	directCmd.MarkFlagRequired("filename")
}

// scanDirectRequest represents a single direct scan request containing
// the target domain information. This struct is used to pass scan
// parameters to the scanning worker goroutines.
type scanDirectRequest struct {
	// Domain is the target domain or hostname to scan
	Domain string
}

// parseHTTPResponse parses a raw HTTP response string and extracts key information.
//
// This function parses HTTP response headers to extract status code, server information,
// and location headers. It's designed to handle various HTTP response formats and
// provides essential information for security scanning and web service enumeration.
//
// Parameters:
//   - response: Raw HTTP response string including status line and headers
//
// Returns:
//   - statusCode: HTTP status code (200, 404, 301, etc.)
//   - server: Server header value (e.g., "nginx/1.18.0", "Apache/2.4.41")
//   - location: Location header value for redirects
//
// Example:
//
//	status, server, location := parseHTTPResponse("HTTP/1.1 200 OK\r\nServer: nginx\r\n...")
func parseHTTPResponse(response string) (statusCode int, server string, location string) {
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
			break // End of headers
		}

		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[9:])
		}
	}

	return statusCode, server, location
}

// scanDirect performs a direct HTTP/HTTPS scan on a single target domain.
//
// This function implements the core scanning logic for direct connections.
// It establishes a connection to the target, sends an HTTP request, reads
// the response, and extracts relevant information for security assessment.
//
// The function handles various timeout scenarios, connection failures, and
// response parsing. It filters results based on configured criteria and
// reports successful scans to the queue scanner context.
//
// Parameters:
//   - c: Queue scanner context for logging and result reporting
//   - p: Scan parameters containing the target domain information
func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	// Determine port based on protocol
	port := "80"
	if scanDirectFlagHttps {
		port = "443"
	}

	address := fmt.Sprintf("%s:%s", req.Domain, port)

	// Establish connection with timeout (IPv4 only)
	var conn net.Conn
	var err error
	timeout := time.Duration(scanDirectFlagTimeoutConnect) * time.Second

	if scanDirectFlagHttps {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp4", address, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp4", address, timeout)
	}

	if err != nil {
		return // Connection failed, skip this target
	}
	defer conn.Close()

	// Set overall timeout for the request
	conn.SetDeadline(time.Now().Add(time.Duration(scanDirectFlagTimeoutRequest) * time.Second))

	method := scanDirectFlagMethod
	if method == "" {
		method = "HEAD"
	}

	// Craft HTTP request with proper headers
	httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, req.Domain)

	// Send HTTP request
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return // Failed to send request
	}

	// Read response with buffer
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return // Failed to read response
	}

	// Parse HTTP response
	response := string(buffer[:n])
	statusCode, hServer, hLocation := parseHTTPResponse(response)

	// Filter results based on Location header if configured
	if scanDirectFlagHideLocation != "" && hLocation == scanDirectFlagHideLocation {
		return
	}

	// Extract IP address from connection
	ip := "unknown"
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
			ip = tcpAddr.IP.String()
		}
	}

	// Format and report successful scan result
	formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ip, statusCode, hServer, req.Domain)
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

// scanDirectRun is the main execution function for the direct scan command.
//
// This function orchestrates the direct scanning process by reading the input file,
// setting up the queue scanner with the specified number of threads, and
// initiating the scanning process for all target domains.
//
// The function handles file I/O, error reporting, result formatting, and
// progress tracking throughout the scanning process.
//
// Parameters:
//   - cmd: The Cobra command instance (unused but required by interface)
//   - args: Command line arguments (unused but required by interface)
func scanDirectRun(cmd *cobra.Command, args []string) {
	// Read target domains from input file
	hosts, err := ReadLinesFromFile(scanDirectFlagFilename)
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
	for _, domain := range hosts {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: &scanDirectRequest{
				Domain: domain,
			},
		})
	}

	// Configure output file if specified
	queueScanner.SetOutputFile(scanDirectFlagOutput)

	// Start the scanning process
	queueScanner.Start()
}
