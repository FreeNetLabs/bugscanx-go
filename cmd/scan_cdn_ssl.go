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

// scanCdnSslCmd performs SSL-based proxy scanning through CDN endpoints.
var scanCdnSslCmd = &cobra.Command{
	Use:     "cdn-ssl",
	Short:   "Scan using CDN SSL proxy with payload injection to SSL targets.",
	Example: "  bugscanx-go cdn-ssl --filename proxy.txt --target sslsite.com\n  bugscanx-go cdn-ssl --cidr 10.0.0.0/8 --target sslsite.com --payload test",
	Run:     runScanCdnSsl,
}

// CDN SSL scanning command flags
var (
	cdnSslFlagProxyCidr         string // CIDR range for CDN proxy IPs
	cdnSslFlagProxyHost         string // Single CDN proxy host to test
	cdnSslFlagProxyHostFilename string // File containing CDN proxy hosts
	cdnSslFlagProxyPort         int    // Port for CDN SSL connections (default 443)
	cdnSslFlagBug               string // Bug/domain for SNI when proxy is IP
	cdnSslFlagMethod            string // HTTP method for CDN SSL requests
	cdnSslFlagTarget            string // Target domain for CDN SSL requests
	cdnSslFlagPath              string // Request path template
	cdnSslFlagScheme            string // URL scheme (ws://, http://, etc.)
	cdnSslFlagProtocol          string // HTTP protocol version
	cdnSslFlagPayload           string // Custom payload template
	cdnSslFlagTimeout           int    // TLS handshake timeout in seconds
	cdnSslFlagOutput            string // Output file for successful results
)

// init sets up the CDN SSL command with flags and configuration.
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

// scanCdnSsl tests CDN SSL proxy by establishing TLS connection and sending HTTP requests.
func scanCdnSsl(c *queuescanner.Ctx, data any) {
	proxyHost := data.(string)

	// Calculate bug value for this proxy host
	regexpIsIP := regexp.MustCompile(`\d+$`)
	bug := cdnSslFlagBug
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

	var conn net.Conn
	var err error

	proxyHostPort := net.JoinHostPort(proxyHost, fmt.Sprintf("%d", cdnSslFlagProxyPort))
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
				c.LogReplacef("%s:%d - Dial Timeout", proxyHost, cdnSslFlagProxyPort)
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
		ServerName:         bug,  // Use bug as SNI hostname
		InsecureSkipVerify: true, // Skip certificate verification
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
		// Prepare and send payload over TLS connection using flag values
		payload := getScanCdnSslPayloadDecoded(bug)
		payload = strings.ReplaceAll(payload, "[host]", cdnSslFlagTarget)
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

// getScanCdnSslPayloadDecoded replaces template placeholders with actual values for CDN SSL.
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

// runScanCdnSsl orchestrates CDN SSL scanning from various proxy sources.
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

	// Process each CDN proxy host and add to scan queue
	for proxyHost := range proxyHostList {
		// Add just the proxy host to the queue
		queueScanner.Add(proxyHost)
	}

	// Display SSL payload being used
	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())

	// Configure output and start CDN SSL scanning
	queueScanner.SetOutputFile(cdnSslFlagOutput)
	queueScanner.Start()
}
