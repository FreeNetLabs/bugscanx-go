package cmd

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Scan hosts using TCP ping.",
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

	pingCmd.Flags().StringVarP(&pingFlagFilename, "filename", "f", "", "domain list filename")
	pingCmd.Flags().IntVar(&pingFlagTimeout, "timeout", 2, "timeout in seconds")
	pingCmd.Flags().StringVarP(&pingFlagOutput, "output", "o", "", "output result")
	pingCmd.Flags().IntVar(&pingFlagPort, "port", 80, "port to use")
}

func pingHost(c *queuescanner.Ctx, host string) {
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

	formatted := fmt.Sprintf("%-16s %-20s", ip, host)
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

func pingRun(cmd *cobra.Command, args []string) {
	hosts, err := ReadFile(pingFlagFilename)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%-16s %-20s\n", "IP Address", "Host")
	fmt.Printf("%-16s %-20s\n", "----------", "----")

	queuescanner := queuescanner.NewQueueScanner(globalFlagThreads, pingHost)
	queuescanner.Add(hosts)
	queuescanner.SetOutputFile(pingFlagOutput)
	queuescanner.SetPrintInterval(globalFlagPrintInterval)
	queuescanner.Start()
}
