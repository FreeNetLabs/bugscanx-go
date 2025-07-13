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
	Use:   "ping",
	Short: "Scan hosts using TCP ping",
	Run:   pingRun,
}

var (
	pingFlagFilename string
	pingFlagTimeout  int
	pingFlagOutput   string
	pingFlagPort     int
)

func init() {
	rootCmd.AddCommand(pingCmd)

	pingCmd.Flags().StringVarP(&pingFlagFilename, "filename", "f", "", "File containing hosts to ping (required)")
	pingCmd.Flags().IntVar(&pingFlagTimeout, "timeout", 2, "Ping timeout in seconds")
	pingCmd.Flags().StringVarP(&pingFlagOutput, "output", "o", "", "File to save results")
	pingCmd.Flags().IntVar(&pingFlagPort, "port", 80, "Port to use for TCP ping")

	pingCmd.MarkFlagRequired("filename")
}

func pingRun(cmd *cobra.Command, args []string) {

	hosts, err := readHostsFromFile(pingFlagFilename)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	fmt.Printf("%-15s %-20s\n", "Status", "Host")
	fmt.Printf("%-15s %-20s\n", "--------", "--------")

	scanner := queuescanner.NewQueueScanner(globalFlagThreads, pingHost)
	for _, host := range hosts {
		scanner.Add(&queuescanner.QueueScannerScanParams{Name: host, Data: host})
	}

	scanner.Start(func(ctx *queuescanner.Ctx) {
		fmt.Printf("Success: %d\n", len(ctx.ScanSuccessList))
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

	ctx.ScanSuccess(host, func() {
		ctx.Log(fmt.Sprintf("%-15s%-20s", "succeeded:", host))
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
