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

// scanProxyCmd performs HTTP proxy scanning with custom payloads.
var scanProxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Scan using a proxy with payload to a target.",
	Example: "  bugscanx-go proxy --cidr 192.168.1.0/24 --target example.com\n  bugscanx-go proxy --filename proxy.txt --target example.com --payload test",
	Run:     runScanProxy,
}

// Proxy scanning command flags
var (
	scanProxyFlagProxyCidr         string // CIDR range for proxy IP generation
	scanProxyFlagProxyHost         string // Single proxy host to test
	scanProxyFlagProxyHostFilename string // File containing proxy hosts
	scanProxyFlagProxyPort         int    // Port for proxy connections
	scanProxyFlagBug               string // Domain to use when proxy is IP
	scanProxyFlagMethod            string // HTTP method for requests
	scanProxyFlagTarget            string // Target server for proxy requests
	scanProxyFlagPath              string // Request path
	scanProxyFlagProtocol          string // HTTP protocol version
	scanProxyFlagPayload           string // Custom payload template
	scanProxyFlagTimeout           int    // Connection timeout in seconds
	scanProxyFlagOutput            string // Output file for successful results
)

// init sets up the proxy command with flags and configuration.
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

// scanProxy tests a proxy server by sending HTTP requests and analyzing responses.
func scanProxy(c *queuescanner.Ctx, proxyHost string) {

	// Calculate bug value for this proxy host
	regexpIsIP := regexp.MustCompile(`\d+$`)
	bug := scanProxyFlagBug
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

	var conn net.Conn
	var err error
	dnsErr := new(net.DNSError)

	proxyHostPort := net.JoinHostPort(proxyHost, fmt.Sprintf("%d", scanProxyFlagProxyPort))
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
		// Prepare and send payload using flag values
		payload := getScanProxyPayloadDecoded(bug)
		payload = strings.ReplaceAll(payload, "[host]", scanProxyFlagTarget)
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

// getScanProxyPayloadDecoded replaces template placeholders with actual values.
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

// runScanProxy orchestrates the proxy scanning process from various sources.
func runScanProxy(cmd *cobra.Command, args []string) {
    var proxyHosts []string

    // Add single host from flag
    if scanProxyFlagProxyHost != "" {
        proxyHosts = append(proxyHosts, scanProxyFlagProxyHost)
    }

    // Add hosts from file
    if scanProxyFlagProxyHostFilename != "" {
        lines, err := ReadLines(scanProxyFlagProxyHostFilename)
        if err != nil {
            fmt.Println(err.Error())
            os.Exit(1)
        }
        proxyHosts = append(proxyHosts, lines...)
    }

    // Add hosts from CIDR range
    if scanProxyFlagProxyCidr != "" {
        cidrHosts, err := IPsFromCIDR(scanProxyFlagProxyCidr)
        if err != nil {
            fmt.Printf("Converting IP list from CIDR error: %s\n", err.Error())
            os.Exit(1)
        }
        proxyHosts = append(proxyHosts, cidrHosts...)
    }

    // Initialize queue scanner
    queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanProxy)

    // Add all collected proxy hosts at once (slice stored only once)
    queueScanner.Add(proxyHosts)

    // Display payload being used
    fmt.Printf("%s\n\n", getScanProxyPayloadDecoded())

    // Configure output and start scanning
    queueScanner.SetOutputFile(scanProxyFlagOutput)
    queueScanner.Start()
}
