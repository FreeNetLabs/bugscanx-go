package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var sniCmd = &cobra.Command{
	Use:   "sni",
	Short: "Scan server name indication (SNI) list from file.",
	Run:   runScanSNI,
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
}

func scanSNI(ctx *queuescanner.Ctx, host string) {
	conn, err := net.DialTimeout("tcp", host+":443", 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		ip = remoteAddr.String()
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	handshakeCtx, cancel := context.WithTimeout(context.Background(), time.Duration(sniFlagTimeout)*time.Second)
	defer cancel()

	err = tlsConn.HandshakeContext(handshakeCtx)
	if err != nil {
		return
	}

	formatted := fmt.Sprintf("%-16s %-20s", ip, host)
	ctx.ScanSuccess(formatted)
	ctx.Log(formatted)
}

func runScanSNI(cmd *cobra.Command, args []string) {
	lines, err := ReadFile(sniFlagFilename)
	if err != nil {
		fatal(err)
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

	qs := queuescanner.New(globalFlagThreads, scanSNI)
	qs.SetOptions(domains, sniFlagOutput, globalFlagStatInterval)
	qs.Start()
}
