package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var pingCmd = &cobra.Command{
	Use:     "ping",
	Short:   "Scan hosts using TCP ping.",
	Long:    "Perform a fast TCP ping scan on a list of hosts to check their reachability. Supports custom ports, timeouts, and output file options. Useful for quickly identifying live hosts.",
	Example: "  bugscanx-go ping -f hosts.txt\n  bugscanx-go ping -f hosts.txt --port 443 --timeout 5",
	Run:     pingRun,
}

var (
	pingFlagFilename string
	pingFlagTimeout  int
	pingFlagOutput   string
	pingFlagPort     int
)

func init() {
	rootCmd.AddCommand(pingCmd)

	pingCmd.Flags().StringVarP(&pingFlagFilename, "filename", "f", "", "domain list filename")
	pingCmd.Flags().IntVar(&pingFlagTimeout, "timeout", 2, "timeout in seconds")
	pingCmd.Flags().StringVarP(&pingFlagOutput, "output", "o", "", "output result")
	pingCmd.Flags().IntVar(&pingFlagPort, "port", 80, "port to use")

	pingCmd.MarkFlagRequired("filename")
}

func pingRun(cmd *cobra.Command, args []string) {

	hosts, err := readHostsFromFile(pingFlagFilename)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	fmt.Printf("%-16s %-20s\n", "IP Address", "Host")
	fmt.Printf("%-16s %-20s\n", "----------", "----")

	scanner := queuescanner.NewQueueScanner(globalFlagThreads, pingHost)
	for _, host := range hosts {
		scanner.Add(&queuescanner.QueueScannerScanParams{Name: host, Data: host})
	}

	scanner.Start(func(ctx *queuescanner.Ctx) {
		if pingFlagOutput != "" {
			writeResultsToFile(pingFlagOutput, ctx)
		}
	})
}

func readHostsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := scanner.Text()
		if host != "" {
			hosts = append(hosts, host)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

func pingHost(ctx *queuescanner.Ctx, params *queuescanner.QueueScannerScanParams) {
	host := params.Data.(string)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", pingFlagPort)), time.Duration(pingFlagTimeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	ctx.ScanSuccess(host, func() {
		ctx.Log(fmt.Sprintf("%-16s %-20s", ip, host))
	})
}

func writeResultsToFile(filename string, ctx *queuescanner.Ctx) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, success := range ctx.ScanSuccessList {
		writer.WriteString(fmt.Sprintf("%v\n", success))
	}
}
