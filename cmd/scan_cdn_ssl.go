package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var cdnSSLCmd = &cobra.Command{
	Use:   "cdn-ssl",
	Short: "Scan using CDN SSL proxy with payload injection to SSL targets.",
	Run:   runScanCDNSSL,
}

var (
	cdnSSLFlagProxyCIDR         string
	cdnSSLFlagProxyHost         string
	cdnSSLFlagProxyHostFilename string
	cdnSSLFlagProxyPort         int
	cdnSSLFlagBug               string
	cdnSSLFlagMethod            string
	cdnSSLFlagTarget            string
	cdnSSLFlagPath              string
	cdnSSLFlagScheme            string
	cdnSSLFlagProtocol          string
	cdnSSLFlagPayload           string
	cdnSSLFlagTimeout           int
	cdnSSLFlagOutput            string
)

func init() {
	rootCmd.AddCommand(cdnSSLCmd)

	cdnSSLCmd.Flags().StringVarP(&cdnSSLFlagProxyCIDR, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagProxyHost, "proxy", "", "cdn proxy without port")
	cdnSSLCmd.Flags().StringVarP(&cdnSSLFlagProxyHostFilename, "filename", "f", "", "cdn proxy filename without port")
	cdnSSLCmd.Flags().IntVarP(&cdnSSLFlagProxyPort, "port", "p", 443, "proxy port")
	cdnSSLCmd.Flags().StringVarP(&cdnSSLFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	cdnSSLCmd.Flags().StringVarP(&cdnSSLFlagMethod, "method", "M", "HEAD", "request method")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagTarget, "target", "", "target domain cdn")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagPath, "path", "[scheme][bug]", "request path")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagScheme, "scheme", "ws://", "request scheme")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	cdnSSLCmd.Flags().StringVar(&cdnSSLFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy")
	cdnSSLCmd.Flags().IntVar(&cdnSSLFlagTimeout, "timeout", 3, "handshake timeout")
	cdnSSLCmd.Flags().StringVarP(&cdnSSLFlagOutput, "output", "o", "", "output result")
}

func scanCDNSSL(ctx *queuescanner.Ctx, host string) {
	bug := cdnSSLFlagBug
	if bug == "" {
		if ipRegex.MatchString(host) {
			bug = cdnSSLFlagTarget
		} else {
			bug = host
		}
	}

	if cdnSSLFlagPath == "/" {
		bug = cdnSSLFlagTarget
	}

	address := net.JoinHostPort(host, strconv.Itoa(cdnSSLFlagProxyPort))

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         bug,
		InsecureSkipVerify: true,
	})

	handshakeCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cdnSSLFlagTimeout)*time.Second)
	defer cancel()

	err = tlsConn.HandshakeContext(handshakeCtx)
	if err != nil {
		return
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer timeoutCancel()

	resultCh := make(chan bool)

	go func() {
		payload := getScanCDNSSLPayloadDecoded(bug)
		payload = strings.ReplaceAll(payload, "[host]", cdnSSLFlagTarget)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		_, err = tlsConn.Write([]byte(payload))
		if err != nil {
			return
		}

		responseLines := []string{}
		scanner := bufio.NewScanner(tlsConn)
		isPrefix := true

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}
			if isPrefix || strings.HasPrefix(line, "Location") || strings.HasPrefix(line, "Server") {
				isPrefix = false
				responseLines = append(responseLines, line)
			}
		}

		if len(responseLines) == 0 || !strings.Contains(responseLines[0], " 101 ") {
			ctx.Log(fmt.Sprintf("%-32s  %s", address, strings.Join(responseLines, " -- ")))
			return
		}

		formatted := fmt.Sprintf("%-32s  %s", address, strings.Join(responseLines, " -- "))
		ctx.ScanSuccess(formatted)
		ctx.Log(formatted)

		resultCh <- true
	}()

	select {
	case <-resultCh:
		return
	case <-timeoutCtx.Done():
		return
	}
}

func getScanCDNSSLPayloadDecoded(bug ...string) string {
	payload := cdnSSLFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", strings.ToUpper(cdnSSLFlagMethod))
	payload = strings.ReplaceAll(payload, "[path]", cdnSSLFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSSLFlagScheme)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSSLFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanCDNSSL(cmd *cobra.Command, args []string) {
	var proxyHosts []string

	if cdnSSLFlagProxyHost != "" {
		proxyHosts = append(proxyHosts, cdnSSLFlagProxyHost)
	}

	if cdnSSLFlagProxyHostFilename != "" {
		lines, err := ReadFile(cdnSSLFlagProxyHostFilename)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, lines...)
	}

	if cdnSSLFlagProxyCIDR != "" {
		cidrHosts, err := IPsFromCIDR(cdnSSLFlagProxyCIDR)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, cidrHosts...)
	}

	qs := queuescanner.New(globalFlagThreads, scanCDNSSL)
	fmt.Printf("%s\n\n", getScanCDNSSLPayloadDecoded())
	qs.SetOptions(proxyHosts, cdnSSLFlagOutput, globalFlagStatInterval)
	qs.Start()
}
