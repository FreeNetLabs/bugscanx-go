package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

// scanProxyCmd represents the proxy scanning command.
// This command performs HTTP proxy scanning by sending specially crafted
// requests through potential proxy servers to test for proxy functionality
// and potential vulnerabilities. It's particularly useful for discovering
// open proxies and testing proxy configurations.
var scanProxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Scan using a proxy with payload to a target.",
	Example: "  bugscanx-go proxy --cidr 192.168.1.0/24 --target example.com\n  bugscanx-go proxy --filename proxy.txt --target example.com --payload test",
	Run:     runScanProxy,
}

// Proxy scanning command flags
var (
	// scanProxyFlagProxyCidr specifies a CIDR range to generate proxy IP addresses
	scanProxyFlagProxyCidr string

	// scanProxyFlagProxyHost specifies a single proxy host to test
	scanProxyFlagProxyHost string

	// scanProxyFlagProxyHostFilename specifies a file containing proxy hosts
	scanProxyFlagProxyHostFilename string

	// scanProxyFlagProxyPort specifies the port to use for proxy connections
	scanProxyFlagProxyPort int

	// scanProxyFlagBug specifies the bug/domain to use in requests when proxy is an IP
	scanProxyFlagBug string

	// scanProxyFlagMethod specifies the HTTP method for proxy requests
	scanProxyFlagMethod string

	// scanProxyFlagTarget specifies the target server for proxy requests
	scanProxyFlagTarget string

	// scanProxyFlagPath specifies the request path for proxy requests
	scanProxyFlagPath string

	// scanProxyFlagProtocol specifies the HTTP protocol version
	scanProxyFlagProtocol string

	// scanProxyFlagPayload specifies the custom payload template for proxy requests
	scanProxyFlagPayload string

	// scanProxyFlagTimeout sets the proxy connection timeout in seconds
	scanProxyFlagTimeout int

	// scanProxyFlagOutput specifies the output file to save successful proxy scan results
	scanProxyFlagOutput string
)

// init initializes the proxy command and its flags.
// This function is automatically called when the package is imported
// and sets up the command configuration, flags, and validation rules.
func init() {
	// Add the proxy command to the root command
	rootCmd.AddCommand(scanProxyCmd)

	// Define command-specific flags with appropriate defaults
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyCidr, "cidr", "c", "", "cidr proxy to scan e.g. 104.16.0.0/24")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProxyHost, "proxy", "", "proxy without port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyHostFilename, "filename", "f", "", "proxy filename without port")
	scanProxyCmd.Flags().IntVarP(&scanProxyFlagProxyPort, "port", "p", 80, "proxy port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagMethod, "method", "M", "GET", "request method")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagTarget, "target", "", "target server (response must be 101)")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagPath, "path", "/", "request path")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanProxyCmd.Flags().StringVar(
		&scanProxyFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught proxy",
	)
	scanProxyCmd.Flags().IntVar(&scanProxyFlagTimeout, "timeout", 3, "handshake timeout")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagOutput, "output", "o", "", "output result")

	// Normalize method flag to uppercase
	scanProxyFlagMethod = strings.ToUpper(scanProxyFlagMethod)
}

// scanProxyRequest represents a single proxy scan request containing
// all necessary parameters for testing a proxy server. This struct
// encapsulates the proxy configuration and request details.
type scanProxyRequest struct {
	// ProxyHost is the IP address or hostname of the proxy server
	ProxyHost string

	// ProxyPort is the port number of the proxy server
	ProxyPort int

	// Bug is the hostname to use in the Host header (for IP-based proxies)
	Bug string

	// Method is the HTTP method to use for the request
	Method string

	// Target is the target server to request through the proxy
	Target string

	// Payload is the complete HTTP request payload to send
	Payload string
}

// scanProxy performs a proxy scan test on a single proxy server.
//
// This function establishes a connection to the proxy server and sends
// a specially crafted HTTP request to test proxy functionality. It analyzes
// the response to determine if the proxy is working correctly and reports
// various response codes and headers.
//
// The function implements timeout handling, error recovery, and response
// parsing to provide comprehensive proxy testing capabilities. It's particularly
// effective for identifying misconfigurations and potential security issues.
//
// Parameters:
//   - c: Queue scanner context for logging and result reporting
//   - p: Scan parameters containing the proxy request configuration
func scanProxy(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanProxyRequest)
	if !ok {
		return // Invalid request data
	}

	var conn net.Conn
	var err error
	dnsErr := new(net.DNSError)

	proxyHostPort := fmt.Sprintf("%s:%d", req.ProxyHost, req.ProxyPort)
	dialCount := 0

	// Retry logic for connection establishment
	for {
		dialCount++
		if dialCount > 3 {
			return // Max retries reached
		}

		// Attempt connection to proxy
		conn, err = net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
		if err != nil {
			// Handle specific error types
			if errors.As(err, &dnsErr) {
				return // DNS resolution failed, don't retry
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue // Retry on timeout
			}
			if opError, ok := err.(*net.OpError); ok {
				if syscalErr, ok := opError.Err.(*os.SyscallError); ok {
					if syscalErr.Err.Error() == "network is unreachable" {
						return // Network unreachable, don't retry
					}
				}
			}
			return // Other errors, give up
		}
		defer conn.Close()
		break
	}

	// Set up timeout context for response handling
	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	// Handle proxy request and response in goroutine
	go func() {
		// Prepare and send payload
		payload := req.Payload
		payload = strings.ReplaceAll(payload, "[host]", req.Target)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		_, err = conn.Write([]byte(payload))
		if err != nil {
			chanResult <- false
			return
		}

		// Read and parse response
		scanner := bufio.NewScanner(conn)
		isPrefix := true
		responseLines := make([]string, 0)

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break // End of headers
			}
			// Collect important response lines
			if isPrefix || strings.HasPrefix(line, "Location") || strings.HasPrefix(line, "Server") {
				isPrefix = false
				responseLines = append(responseLines, line)
			}
		}

		if len(responseLines) == 0 {
			chanResult <- false
			return
		}

		// Check for specific successful responses
		if strings.Contains(responseLines[0], " 302 ") {
			chanResult <- true
			return
		}

		// Format and report result
		resultString := fmt.Sprintf("%-32s %s", proxyHostPort, strings.Join(responseLines, " -- "))
		c.ScanSuccess(resultString)
		c.Log(resultString)

		chanResult <- true
	}()

	// Wait for result or timeout
	select {
	case <-chanResult:
		// Request completed
	case <-ctxResultTimeout.Done():
		// Request timed out
	}
}

// getScanProxyPayloadDecoded generates the final payload string by replacing
// template placeholders with actual values.
//
// This function takes the payload template and substitutes various placeholders
// with their actual values, including HTTP method, path, protocol, and bug host.
// It's used to generate the final HTTP request that will be sent through the proxy.
//
// Parameters:
//   - bug: Optional bug hostname to substitute in the payload
//
// Returns:
//   - string: The processed payload with all placeholders replaced
//
// Template placeholders:
//   - [method]: HTTP method (GET, POST, etc.)
//   - [path]: Request path
//   - [protocol]: HTTP protocol version
//   - [bug]: Bug hostname (if provided)
func getScanProxyPayloadDecoded(bug ...string) string {
	payload := scanProxyFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", scanProxyFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", scanProxyFlagPath)
	payload = strings.ReplaceAll(payload, "[protocol]", scanProxyFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

// runScanProxy is the main execution function for the proxy scan command.
//
// This function orchestrates the proxy scanning process by collecting proxy
// hosts from various sources (CIDR, single host, or file), configuring scan
// parameters, and initiating the scanning process using the queue scanner.
//
// The function handles multiple input methods, generates appropriate bug
// values for different proxy types, and provides feedback about the payload
// being used for scanning.
//
// Parameters:
//   - cmd: The Cobra command instance (unused but required by interface)
//   - args: Command line arguments (unused but required by interface)
func runScanProxy(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	// Collect proxy hosts from single host flag
	if scanProxyFlagProxyHost != "" {
		proxyHostList[scanProxyFlagProxyHost] = true
	}

	// Collect proxy hosts from file
	if scanProxyFlagProxyHostFilename != "" {
		lines, err := ReadLinesFromFile(scanProxyFlagProxyHostFilename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		for _, proxyHost := range lines {
			proxyHostList[proxyHost] = true
		}
	}

	// Collect proxy hosts from CIDR range
	if scanProxyFlagProxyCidr != "" {
		proxyHostListFromCidr, err := ipListFromCidr(scanProxyFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting ip list from cidr error: %s", err.Error())
			os.Exit(1)
		}

		for _, proxyHost := range proxyHostListFromCidr {
			proxyHostList[proxyHost] = true
		}
	}

	// Initialize queue scanner
	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanProxy)
	regexpIsIP := regexp.MustCompile(`\d+$`)

	// Process each proxy host and add to scan queue
	for proxyHost := range proxyHostList {
		bug := scanProxyFlagBug

		// Determine appropriate bug value
		if bug == "" {
			if regexpIsIP.MatchString(proxyHost) {
				bug = scanProxyFlagTarget // Use target for IP proxies
			} else {
				bug = proxyHost // Use proxy hostname for domain proxies
			}
		}

		// Special case for root path
		if scanProxyFlagPath == "/" {
			bug = scanProxyFlagTarget
		}

		// Add scan job to queue
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, scanProxyFlagProxyPort, scanProxyFlagTarget),
			Data: &scanProxyRequest{
				ProxyHost: proxyHost,
				ProxyPort: scanProxyFlagProxyPort,
				Bug:       bug,
				Method:    scanProxyFlagMethod,
				Target:    scanProxyFlagTarget,
				Payload:   getScanProxyPayloadDecoded(bug),
			},
		})
	}

	// Display payload being used
	fmt.Printf("%s\n\n", getScanProxyPayloadDecoded())

	// Configure output and start scanning
	queueScanner.SetOutputFile(scanProxyFlagOutput)
	queueScanner.Start()
}
