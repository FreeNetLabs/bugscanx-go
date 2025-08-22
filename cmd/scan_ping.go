package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

// pingCmd represents the TCP ping scanning command.
// This command performs TCP connectivity tests to determine if hosts
// are reachable on specific ports. Unlike ICMP ping, TCP ping works
// through firewalls and provides more accurate results for web services.
var pingCmd = &cobra.Command{
	Use:     "ping",
	Short:   "Scan hosts using TCP ping.",
	Example: "  bugscanx-go ping -f hosts.txt\n  bugscanx-go ping -f hosts.txt --port 443 --timeout 5",
	Run:     pingRun,
}

// Ping command flags
var (
	// pingFlagFilename specifies the input file containing the list of hosts to ping
	pingFlagFilename string

	// pingFlagTimeout sets the connection timeout in seconds for each ping attempt
	pingFlagTimeout int

	// pingFlagOutput specifies the output file to save successful ping results
	pingFlagOutput string

	// pingFlagPort specifies the TCP port to use for ping attempts
	pingFlagPort int
)

// init initializes the ping command and its flags.
// This function is automatically called when the package is imported
// and sets up the command configuration, flags, and validation rules.
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

// pingHost performs a TCP ping test on a single host.
//
// This function attempts to establish a TCP connection to the target host
// on the specified port. If the connection is successful, it extracts the
// IP address and reports the result. This method is more reliable than
// ICMP ping for testing web service availability.
//
// The function handles connection timeouts gracefully and only reports
// successful connections to avoid flooding the output with failures.
//
// Parameters:
//   - ctx: Queue scanner context for logging and result reporting
//   - params: Scan parameters containing the target host information
func pingHost(ctx *queuescanner.Ctx, params *queuescanner.QueueScannerScanParams) {
	host := params.Data.(string)

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

// pingRun is the main execution function for the ping command.
//
// This function orchestrates the TCP ping process by reading the input file,
// setting up the queue scanner with the specified number of threads, and
// initiating the ping process for all target hosts.
//
// The function handles file I/O, error reporting, result formatting, and
// progress tracking throughout the ping process. It provides a clean
// tabulated output showing IP addresses and corresponding hostnames.
//
// Parameters:
//   - cmd: The Cobra command instance (unused but required by interface)
//   - args: Command line arguments (unused but required by interface)
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
		scanner.Add(&queuescanner.QueueScannerScanParams{Name: host, Data: host})
	}

	// Configure output file if specified
	scanner.SetOutputFile(pingFlagOutput)

	// Start the ping scanning process
	scanner.Start()
}
