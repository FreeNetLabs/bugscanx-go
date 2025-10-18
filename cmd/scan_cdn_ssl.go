package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var cdnSslCmd = &cobra.Command{
	Use:   "cdn-ssl",
	Short: "Scan using CDN SSL proxy with payload injection to SSL targets.",
	Run:   runScanCdnSsl,
}

var (
	cdnSslFlagProxyCidr         string
	cdnSslFlagProxyHost         string
	cdnSslFlagProxyHostFilename string
	cdnSslFlagProxyPort         int
	cdnSslFlagBug               string
	cdnSslFlagMethod            string
	cdnSslFlagTarget            string
	cdnSslFlagPath              string
	cdnSslFlagScheme            string
	cdnSslFlagProtocol          string
	cdnSslFlagPayload           string
	cdnSslFlagTimeout           int
	cdnSslFlagOutput            string
)

func init() {
	rootCmd.AddCommand(cdnSslCmd)

	cdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagProxyHost, "proxy", "", "cdn proxy without port")
	cdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyHostFilename, "filename", "f", "", "cdn proxy filename without port")
	cdnSslCmd.Flags().IntVarP(&cdnSslFlagProxyPort, "port", "p", 443, "proxy port")
	cdnSslCmd.Flags().StringVarP(&cdnSslFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	cdnSslCmd.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagTarget, "target", "", "target domain cdn")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][bug]", "request path")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	cdnSslCmd.Flags().StringVar(&cdnSslFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy")
	cdnSslCmd.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")
	cdnSslCmd.Flags().StringVarP(&cdnSslFlagOutput, "output", "o", "", "output result")

	cdnSslFlagMethod = strings.ToUpper(cdnSslFlagMethod)
}

func scanCdnSsl(c *queuescanner.Ctx, host string) {
	regexpIsIP := regexp.MustCompile(`\d+$`)
	bug := cdnSslFlagBug
	if bug == "" {
		if regexpIsIP.MatchString(host) {
			bug = cdnSslFlagTarget
		} else {
			bug = host
		}
	}

	if cdnSslFlagPath == "/" {
		bug = cdnSslFlagTarget
	}

	proxyHostPort := net.JoinHostPort(host, fmt.Sprintf("%d", cdnSslFlagProxyPort))

	conn, err := net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         bug,
		InsecureSkipVerify: true,
	})

	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(cdnSslFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()

	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		return
	}

	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	go func() {
		payload := getScanCdnSslPayloadDecoded(bug)
		payload = strings.ReplaceAll(payload, "[host]", cdnSslFlagTarget)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		_, err = tlsConn.Write([]byte(payload))
		if err != nil {
			return
		}

		responseLines := make([]string, 0)
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
			c.Log(fmt.Sprintf("%-32s  %s", proxyHostPort, strings.Join(responseLines, " -- ")))
			return
		}

		formatted := fmt.Sprintf("%-32s  %s", proxyHostPort, strings.Join(responseLines, " -- "))
		c.ScanSuccess(formatted)
		c.Log(formatted)

		chanResult <- true
	}()

	select {
	case <-chanResult:
		return
	case <-ctxResultTimeout.Done():
		return
	}
}

func getScanCdnSslPayloadDecoded(bug ...string) string {
	payload := cdnSslFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanCdnSsl(cmd *cobra.Command, args []string) {
	var proxyHosts []string

	if cdnSslFlagProxyHost != "" {
		proxyHosts = append(proxyHosts, cdnSslFlagProxyHost)
	}

	if cdnSslFlagProxyHostFilename != "" {
		lines, err := ReadFile(cdnSslFlagProxyHostFilename)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, lines...)
	}

	if cdnSslFlagProxyCidr != "" {
		cidrHosts, err := IPsFromCIDR(cdnSslFlagProxyCidr)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, cidrHosts...)
	}

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanCdnSsl)
	queueScanner.Add(proxyHosts)
	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())
	queueScanner.SetOutputFile(cdnSslFlagOutput)
	queueScanner.Start()
}
