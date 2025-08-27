package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

// pingCmd performs TCP connectivity tests to determine host reachability.
var pingCmd = &cobra.Command{
	Use:     "ping",
	Short:   "Scan hosts using TCP ping.",
	Example: "  bugscanx-go ping -f hosts.txt\n  bugscanx-go ping -f hosts.txt --port 443 --timeout 5",
	Run:     pingRun,
}

// Ping command flags
var (
	pingFlagFilename string // Input file containing hosts to ping
	pingFlagTimeout  int    // Connection timeout in seconds
	pingFlagOutput   string // Output file for successful results
	pingFlagPort     int    // TCP port to use for ping attempts
)

// init sets up the ping command with flags and validation.
func init() {
	// Add the ping command to the root command
	rootCmd.AddCommand(pingCmd)

	// Define command-specific flags with appropriate defaults
	pingCmd.Flags().StringVarP(&pingFlagFilename, "filename", "f", "", "domain list filename")
	pingCmd.Flags().IntVar(&pingFlagTimeout, "timeout", 2, "timeout in seconds")
	pingCmd.Flags().StringVarP(&pingFlagOutput, "output", "o", "", "output result")
	pingCmd.Flags().IntVar(&pingFlagPort, "port", 80, "port to use")

	// Mark required flags
	pingCmd.MarkFlagRequired("filename")
}

// pingHost performs TCP ping test on a host and reports successful connections.
func pingHost(ctx *queuescanner.Ctx, data any) {
	host := data.(string)

	// Attempt TCP connection with specified timeout
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", pingFlagPort)), time.Duration(pingFlagTimeout)*time.Second)
	if err != nil {
		return // Connection failed, skip this host
	}
	defer conn.Close()

	// Extract IP address from connection
	remoteAddr := conn.RemoteAddr()
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		// Fallback if port parsing fails
		ip = remoteAddr.String()
	}

	// Format and report successful ping result
	formatted := fmt.Sprintf("%-16s %-20s", ip, host)
	ctx.ScanSuccess(formatted)
	ctx.Log(formatted)
}

// pingRun orchestrates the TCP ping process for all target hosts.
func pingRun(cmd *cobra.Command, args []string) {
	// Read target hosts from input file
	hosts, err := ReadLinesFromFile(pingFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Print table headers for results
	fmt.Printf("%-16s %-20s\n", "IP Address", "Host")
	fmt.Printf("%-16s %-20s\n", "----------", "----")

	// Initialize queue scanner with configured thread count
	scanner := queuescanner.NewQueueScanner(globalFlagThreads, pingHost)

	// Add all hosts to the scan queue
	for _, host := range hosts {
		scanner.Add(host)
	}

	// Configure output file if specified
	scanner.SetOutputFile(pingFlagOutput)

	// Start the ping scanning process
	scanner.Start()
}
