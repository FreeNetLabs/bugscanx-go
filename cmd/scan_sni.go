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

// sniCmd performs SNI (Server Name Indication) scanning to verify SSL certificates.
var sniCmd = &cobra.Command{
	Use:     "sni",
	Short:   "Scan server name indication (SNI) list from file.",
	Example: "  bugscanx-go sni -f domains.txt\n  bugscanx-go sni -f domains.txt --deep 2 --timeout 5",
	Run:     runScanSNI,
}

// SNI command flags
var (
	sniFlagFilename string // Input file containing domains for SNI scanning
	sniFlagDeep     int    // Subdomain depth for domain processing
	sniFlagTimeout  int    // TLS handshake timeout in seconds
	sniFlagOutput   string // Output file for successful results
)

// init sets up the SNI command with flags and validation.
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

// scanSNI performs SNI scanning on a domain by establishing TLS connection.
func scanSNI(c *queuescanner.Ctx, data any) {
	domain := data.(string)

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
				c.LogReplacef("%s - Dial Timeout", domain)
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

// runScanSNI orchestrates the SNI scanning process with domain processing.
func runScanSNI(cmd *cobra.Command, args []string) {
	// Read target domains from input file
	lines, err := ReadLines(sniFlagFilename)
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
	queueScanner.Add(domains)

	// Configure output file if specified
	queueScanner.SetOutputFile(sniFlagOutput)

	// Start the SNI scanning process
	queueScanner.Start()
}
