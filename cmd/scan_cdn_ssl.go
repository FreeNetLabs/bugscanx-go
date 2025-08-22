package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

// scanCdnSslCmd represents the CDN SSL scanning command.
// This command performs SSL-based proxy scanning through CDN endpoints
// by establishing TLS connections and sending specially crafted requests.
// It's particularly useful for testing CDN configurations and identifying
// SSL-enabled proxy endpoints that might be misconfigured.
var scanCdnSslCmd = &cobra.Command{
	Use:     "cdn-ssl",
	Short:   "Scan using CDN SSL proxy with payload injection to SSL targets.",
	Example: "  bugscanx-go cdn-ssl --filename proxy.txt --target sslsite.com\n  bugscanx-go cdn-ssl --cidr 10.0.0.0/8 --target sslsite.com --payload test",
	Run:     runScanCdnSsl,
}

// CDN SSL scanning command flags
var (
	// cdnSslFlagProxyCidr specifies a CIDR range to generate CDN proxy IP addresses
	cdnSslFlagProxyCidr string

	// cdnSslFlagProxyHost specifies a single CDN proxy host to test
	cdnSslFlagProxyHost string

	// cdnSslFlagProxyHostFilename specifies a file containing CDN proxy hosts
	cdnSslFlagProxyHostFilename string

	// cdnSslFlagProxyPort specifies the port to use for CDN SSL connections (default 443)
	cdnSslFlagProxyPort int

	// cdnSslFlagBug specifies the bug/domain to use in SNI when proxy is an IP
	cdnSslFlagBug string

	// cdnSslFlagMethod specifies the HTTP method for CDN SSL requests
	cdnSslFlagMethod string

	// cdnSslFlagTarget specifies the target domain for CDN SSL requests
	cdnSslFlagTarget string

	// cdnSslFlagPath specifies the request path template for CDN SSL requests
	cdnSslFlagPath string

	// cdnSslFlagScheme specifies the URL scheme (ws://, http://, etc.)
	cdnSslFlagScheme string

	// cdnSslFlagProtocol specifies the HTTP protocol version
	cdnSslFlagProtocol string

	// cdnSslFlagPayload specifies the custom payload template for CDN SSL requests
	cdnSslFlagPayload string

	// cdnSslFlagTimeout sets the TLS handshake timeout in seconds
	cdnSslFlagTimeout int

	// cdnSslFlagOutput specifies the output file to save successful CDN SSL scan results
	cdnSslFlagOutput string
)

// init initializes the CDN SSL command and its flags.
// This function is automatically called when the package is imported
// and sets up the command configuration, flags, and validation rules.
func init() {
	// Add the CDN SSL command to the root command
	rootCmd.AddCommand(scanCdnSslCmd)

	// Define command-specific flags with appropriate defaults for SSL scanning
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProxyHost, "proxy", "", "cdn proxy without port")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyHostFilename, "filename", "f", "", "cdn proxy filename without port")
	scanCdnSslCmd.Flags().IntVarP(&cdnSslFlagProxyPort, "port", "p", 443, "proxy port")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagTarget, "target", "", "target domain cdn")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][bug]", "request path")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanCdnSslCmd.Flags().StringVar(
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy",
	)
	scanCdnSslCmd.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagOutput, "output", "o", "", "output result")

	// Normalize method flag to uppercase
	cdnSslFlagMethod = strings.ToUpper(cdnSslFlagMethod)
}

// scanCdnSslRequest represents a single CDN SSL scan request containing
// all necessary parameters for testing a CDN SSL proxy server. This struct
// encapsulates the SSL proxy configuration and request details.
type scanCdnSslRequest struct {
	// ProxyHost is the IP address or hostname of the CDN SSL proxy server
	ProxyHost string

	// ProxyPort is the port number of the CDN SSL proxy server (typically 443)
	ProxyPort int

	// Bug is the hostname to use for SNI and Host header
	Bug string

	// Method is the HTTP method to use for the request
	Method string

	// Target is the target domain to request through the CDN SSL proxy
	Target string

	// Payload is the complete HTTP request payload to send over SSL
	Payload string
}

// scanCdnSsl performs a CDN SSL scan test on a single CDN SSL proxy server.
//
// This function establishes a TLS connection to the CDN proxy server and sends
// a specially crafted HTTP request over the encrypted connection. It analyzes
// the response to determine if the CDN SSL proxy is working correctly and
// looks for specific response codes that indicate successful connections.
//
// The function implements comprehensive timeout handling, TLS handshake
// verification, and response parsing specifically tailored for CDN SSL
// proxy testing. It only reports successful connections (HTTP 101 responses)
// which indicate proper WebSocket upgrade handling.
//
// Parameters:
//   - c: Queue scanner context for logging and result reporting
//   - p: Scan parameters containing the CDN SSL request configuration
func scanCdnSsl(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanCdnSslRequest)
	if !ok {
		return // Invalid request data
	}

	var conn net.Conn
	var err error

	proxyHostPort := fmt.Sprintf("%s:%d", req.ProxyHost, req.ProxyPort)
	dialCount := 0

	// Retry logic for connection establishment
	for {
		dialCount++
		if dialCount > 3 {
			return // Max retries reached
		}

		// Attempt TCP connection
		conn, err = net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
		if err != nil {
			// Handle specific error types
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplace(p.Name, "-", "Dial Timeout")
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

	// Establish TLS connection with SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         req.Bug, // Use bug as SNI hostname
		InsecureSkipVerify: true,    // Skip certificate verification
	})

	// Perform TLS handshake with timeout
	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(cdnSslFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()

	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		return // TLS handshake failed
	}

	// Set up timeout context for response handling
	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	// Handle CDN SSL request and response in goroutine
	go func() {
		// Prepare and send payload over TLS connection
		payload := req.Payload
		payload = strings.ReplaceAll(payload, "[host]", req.Target)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		_, err = tlsConn.Write([]byte(payload))
		if err != nil {
			return // Failed to send request
		}

		// Read and parse SSL response
		responseLines := make([]string, 0)
		scanner := bufio.NewScanner(tlsConn)
		isPrefix := true

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

		// Check for successful WebSocket upgrade response (HTTP 101)
		if len(responseLines) == 0 || !strings.Contains(responseLines[0], " 101 ") {
			// Log unsuccessful attempts for debugging
			c.Log(fmt.Sprintf("%-32s  %s", proxyHostPort, strings.Join(responseLines, " -- ")))
			return
		}

		// Format and report successful CDN SSL scan result
		formatted := fmt.Sprintf("%-32s  %s", proxyHostPort, strings.Join(responseLines, " -- "))
		c.ScanSuccess(formatted)
		c.Log(formatted)

		chanResult <- true
	}()

	// Wait for result or timeout
	select {
	case <-chanResult:
		return // Request completed
	case <-ctxResultTimeout.Done():
		return // Request timed out
	}
}

// getScanCdnSslPayloadDecoded generates the final CDN SSL payload string by
// replacing template placeholders with actual values.
//
// This function takes the CDN SSL payload template and substitutes various
// placeholders with their actual values, including HTTP method, path, scheme,
// protocol, and bug host. It's specifically designed for CDN SSL proxy testing.
//
// Parameters:
//   - bug: Optional bug hostname to substitute in the payload
//
// Returns:
//   - string: The processed payload with all placeholders replaced
//
// Template placeholders:
//   - [method]: HTTP method (HEAD, GET, etc.)
//   - [path]: Request path template
//   - [scheme]: URL scheme (ws://, http://, etc.)
//   - [protocol]: HTTP protocol version
//   - [bug]: Bug hostname (if provided)
func getScanCdnSslPayloadDecoded(bug ...string) string {
	payload := cdnSslFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

// runScanCdnSsl is the main execution function for the CDN SSL scan command.
//
// This function orchestrates the CDN SSL scanning process by collecting CDN
// proxy hosts from various sources (CIDR, single host, or file), configuring
// scan parameters specifically for SSL connections, and initiating the scanning
// process using the queue scanner.
//
// The function handles multiple input methods, generates appropriate bug values
// for different CDN proxy types, and provides feedback about the SSL payload
// being used for scanning. It's specifically optimized for CDN SSL proxy testing.
//
// Parameters:
//   - cmd: The Cobra command instance (unused but required by interface)
//   - args: Command line arguments (unused but required by interface)
func runScanCdnSsl(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	// Collect CDN proxy hosts from single host flag
	if cdnSslFlagProxyHost != "" {
		proxyHostList[cdnSslFlagProxyHost] = true
	}

	// Collect CDN proxy hosts from file
	if cdnSslFlagProxyHostFilename != "" {
		lines, err := ReadLinesFromFile(cdnSslFlagProxyHostFilename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		for _, proxyHost := range lines {
			proxyHostList[proxyHost] = true
		}
	}

	// Collect CDN proxy hosts from CIDR range
	if cdnSslFlagProxyCidr != "" {
		proxyHostListFromCidr, err := ipListFromCidr(cdnSslFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting ip list from cidr error: %s", err.Error())
			os.Exit(1)
		}

		for _, proxyHost := range proxyHostListFromCidr {
			proxyHostList[proxyHost] = true
		}
	}

	// Initialize queue scanner for CDN SSL scanning
	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanCdnSsl)
	regexpIsIP := regexp.MustCompile(`\d+$`)

	// Process each CDN proxy host and add to scan queue
	for proxyHost := range proxyHostList {
		bug := cdnSslFlagBug

		// Determine appropriate bug value for SNI
		if bug == "" {
			if regexpIsIP.MatchString(proxyHost) {
				bug = cdnSslFlagTarget // Use target for IP-based CDN proxies
			} else {
				bug = proxyHost // Use proxy hostname for domain-based CDN proxies
			}
		}

		// Special case for root path
		if cdnSslFlagPath == "/" {
			bug = cdnSslFlagTarget
		}

		// Add CDN SSL scan job to queue
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, cdnSslFlagProxyPort, cdnSslFlagTarget),
			Data: &scanCdnSslRequest{
				ProxyHost: proxyHost,
				ProxyPort: cdnSslFlagProxyPort,
				Bug:       bug,
				Method:    cdnSslFlagMethod,
				Target:    cdnSslFlagTarget,
				Payload:   getScanCdnSslPayloadDecoded(bug),
			},
		})
	}

	// Display SSL payload being used
	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())

	// Configure output and start CDN SSL scanning
	queueScanner.SetOutputFile(cdnSslFlagOutput)
	queueScanner.Start()
}
