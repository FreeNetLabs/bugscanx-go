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

var sniCmd = &cobra.Command{
	Use:     "sni",
	Short:   "Scan server name indication (SNI) list from file.",
	Run:     runScanSNI,
}

var (
	sniFlagFilename string
	sniFlagDeep     int
	sniFlagTimeout  int
	sniFlagOutput   string
)

func init() {
	rootCmd.AddCommand(sniCmd)

	sniCmd.Flags().StringVarP(&sniFlagFilename, "filename", "f", "", "domain list filename")
	sniCmd.Flags().IntVarP(&sniFlagDeep, "deep", "d", 0, "deep subdomain")
	sniCmd.Flags().IntVar(&sniFlagTimeout, "timeout", 3, "handshake timeout")
	sniCmd.Flags().StringVarP(&sniFlagOutput, "output", "o", "", "output result")

	sniCmd.MarkFlagRequired("filename")
}

func scanSNI(c *queuescanner.Ctx, domain string) {
	var conn net.Conn
	var err error

	dialCount := 0
	for {
		dialCount++
		if dialCount > 3 {
			return
		}

		conn, err = net.DialTimeout("tcp", domain+":443", 3*time.Second)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplacef("%s - Dial Timeout", domain)
				continue
			}
			return
		}
		defer conn.Close()
		break
	}

	remoteAddr := conn.RemoteAddr()
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(sniFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()

	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		return
	}

	formatted := fmt.Sprintf("%-16s %-20s", ip, domain)
	c.ScanSuccess(formatted)
	c.Log(formatted)
}

func runScanSNI(cmd *cobra.Command, args []string) {
	lines, err := ReadLines(sniFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var domains []string

	for _, domain := range lines {
		if sniFlagDeep > 0 {
			domainSplit := strings.Split(domain, ".")
			if len(domainSplit) >= sniFlagDeep {
				domain = strings.Join(domainSplit[len(domainSplit)-sniFlagDeep:], ".")
			}
		}
		domains = append(domains, domain)
	}

	fmt.Printf("%-16s %-20s\n", "IP Address", "SNI")
	fmt.Printf("%-16s %-20s\n", "----------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanSNI)
	queueScanner.Add(domains)
	queueScanner.SetOutputFile(sniFlagOutput)
	queueScanner.Start()
}
