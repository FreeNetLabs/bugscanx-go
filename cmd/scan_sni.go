package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

// sniCmd represents the Server Name Indication (SNI) scanning command.
// This command performs TLS handshakes with target domains to verify
// SSL certificate validity and server availability. SNI scanning is
// particularly useful for identifying CDN endpoints and SSL-enabled services.
var sniCmd = &cobra.Command{
	Use:     "sni",
	Short:   "Scan server name indication (SNI) list from file.",
	Example: "  bugscanx-go sni -f domains.txt\n  bugscanx-go sni -f domains.txt --deep 2 --timeout 5",
	Run:     runScanSNI,
}

// SNI command flags
var (
	// sniFlagFilename specifies the input file containing the list of domains for SNI scanning
	sniFlagFilename string

	// sniFlagDeep specifies the subdomain depth for domain processing
	// (e.g., 2 for "example.com" from "sub.example.com")
	sniFlagDeep int

	// sniFlagTimeout sets the TLS handshake timeout in seconds
	sniFlagTimeout int

	// sniFlagOutput specifies the output file to save successful SNI scan results
	sniFlagOutput string
)

// init initializes the SNI command and its flags.
// This function is automatically called when the package is imported
// and sets up the command configuration, flags, and validation rules.
func init() {
	// Add the SNI command to the root command
	rootCmd.AddCommand(sniCmd)

	// Define command-specific flags with appropriate defaults
	sniCmd.Flags().StringVarP(&sniFlagFilename, "filename", "f", "", "domain list filename")
	sniCmd.Flags().IntVarP(&sniFlagDeep, "deep", "d", 0, "deep subdomain")
	sniCmd.Flags().IntVar(&sniFlagTimeout, "timeout", 3, "handshake timeout")
	sniCmd.Flags().StringVarP(&sniFlagOutput, "output", "o", "", "output result")

	// Mark required flags
	sniCmd.MarkFlagRequired("filename")
}

// scanSNI performs an SNI (Server Name Indication) scan on a single domain.
//
// This function establishes a TCP connection to port 443 and performs a TLS
// handshake using the domain name as the SNI value. This technique is useful
// for identifying SSL-enabled services and CDN endpoints that respond to
// specific domain names.
//
// The function implements retry logic for connection failures and handles
// various timeout scenarios. It only reports successful TLS handshakes,
// indicating that the domain is properly configured for SSL.
//
// Parameters:
//   - c: Queue scanner context for logging and result reporting
//   - p: Scan parameters containing the target domain information
func scanSNI(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	domain := p.Data.(string)

	var conn net.Conn
	var err error

	// Retry logic for connection establishment
	dialCount := 0
	for {
		dialCount++
		if dialCount > 3 {
			return // Max retries reached
		}

		// Attempt TCP connection to port 443
		conn, err = net.DialTimeout("tcp", domain+":443", 3*time.Second)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplace(p.Name, "-", "Dial Timeout")
				continue // Retry on timeout
			}
			return // Non-timeout error, give up
		}
		defer conn.Close()
		break
	}

	// Extract IP address from established connection
	remoteAddr := conn.RemoteAddr()
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	// Create TLS client connection with SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain, // SNI value
		InsecureSkipVerify: true,   // Skip certificate verification
	})
	defer tlsConn.Close()

	// Perform TLS handshake with timeout
	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(sniFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()

	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		return // Handshake failed
	}

	// Format and report successful SNI scan result
	formatted := fmt.Sprintf("%-16s %-20s", ip, domain)
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

// runScanSNI is the main execution function for the SNI scan command.
//
// This function orchestrates the SNI scanning process by reading the input file,
// processing domains based on the deep flag, setting up the queue scanner with
// the specified number of threads, and initiating the scanning process.
//
// The deep flag allows for domain processing where only the top-level domains
// are extracted from subdomains (e.g., extracting "example.com" from
// "sub.domain.example.com" when deep=2).
//
// Parameters:
//   - cmd: The Cobra command instance (unused but required by interface)
//   - args: Command line arguments (unused but required by interface)
func runScanSNI(cmd *cobra.Command, args []string) {
	// Read target domains from input file
	lines, err := ReadLinesFromFile(sniFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var domains []string

	// Process domains based on deep flag
	for _, domain := range lines {
		if sniFlagDeep > 0 {
			// Extract top-level domain based on deep parameter
			domainSplit := strings.Split(domain, ".")
			if len(domainSplit) >= sniFlagDeep {
				domain = strings.Join(domainSplit[len(domainSplit)-sniFlagDeep:], ".")
			}
		}
		domains = append(domains, domain)
	}

	// Print table headers for results
	fmt.Printf("%-16s %-20s\n", "IP Address", "SNI")
	fmt.Printf("%-16s %-20s\n", "----------", "----")

	// Initialize queue scanner with configured thread count
	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanSNI)

	// Add all domains to the scan queue
	for _, domain := range domains {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: domain,
		})
	}

	// Configure output file if specified
	queueScanner.SetOutputFile(sniFlagOutput)

	// Start the SNI scanning process
	queueScanner.Start()
}
