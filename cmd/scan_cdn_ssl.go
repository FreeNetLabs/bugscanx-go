package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var scanCdnSslCmd = &cobra.Command{
	Use:     "cdn-ssl",
	Short:   "Scan using CDN SSL proxy with payload injection to SSL targets.",
	Example: "  bugscanx-go cdn-ssl --filename proxy.txt --target sslsite.com\n  bugscanx-go cdn-ssl --cidr 10.0.0.0/8 --target sslsite.com --payload test",
	Run:     runScanCdnSsl,
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
	rootCmd.AddCommand(scanCdnSslCmd)

	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProxyHost, "proxy", "", "cdn proxy without port")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyHostFilename, "filename", "f", "", "cdn proxy filename without port")
	scanCdnSslCmd.Flags().IntVarP(&cdnSslFlagProxyPort, "port", "p", 443, "proxy port")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagTarget, "target", "", "target domain cdn")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][bug]", "request path")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanCdnSslCmd.Flags().StringVar(
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy",
	)
	scanCdnSslCmd.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagOutput, "output", "o", "", "output result")

	cdnSslFlagMethod = strings.ToUpper(cdnSslFlagMethod)
}

func scanCdnSsl(c *queuescanner.Ctx, proxyHost string) {
	regexpIsIP := regexp.MustCompile(`\d+$`)
	bug := cdnSslFlagBug
	if bug == "" {
		if regexpIsIP.MatchString(proxyHost) {
			bug = cdnSslFlagTarget
		} else {
			bug = proxyHost
		}
	}

	if cdnSslFlagPath == "/" {
		bug = cdnSslFlagTarget
	}

	var conn net.Conn
	var err error

	proxyHostPort := net.JoinHostPort(proxyHost, fmt.Sprintf("%d", cdnSslFlagProxyPort))
	dialCount := 0

	for {
		dialCount++
		if dialCount > 3 {
			return
		}

		conn, err = net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplacef("%s:%d - Dial Timeout", proxyHost, cdnSslFlagProxyPort)
				continue
			}
			if opError, ok := err.(*net.OpError); ok {
				if syscalErr, ok := opError.Err.(*os.SyscallError); ok {
					if syscalErr.Err.Error() == "network is unreachable" {
						return
					}
				}
			}
			return
		}
		defer conn.Close()
		break
	}

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
		lines, err := ReadLines(cdnSslFlagProxyHostFilename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		proxyHosts = append(proxyHosts, lines...)
	}

	if cdnSslFlagProxyCidr != "" {
		cidrHosts, err := IPsFromCIDR(cdnSslFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting IP list from CIDR error: %s\n", err.Error())
			os.Exit(1)
		}
		proxyHosts = append(proxyHosts, cidrHosts...)
	}

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanCdnSsl)
	queueScanner.Add(proxyHosts)
	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())
	queueScanner.SetOutputFile(cdnSslFlagOutput)
	queueScanner.Start()
}
