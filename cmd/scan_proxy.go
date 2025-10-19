package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Scan using a proxy with payload to a target.",
	Run:   runScanProxy,
}

var (
	proxyFlagProxyCidr         string
	proxyFlagProxyHost         string
	proxyFlagProxyHostFilename string
	proxyFlagProxyPort         int
	proxyFlagBug               string
	proxyFlagMethod            string
	proxyFlagTarget            string
	proxyFlagPath              string
	proxyFlagProtocol          string
	proxyFlagPayload           string
	proxyFlagTimeout           int
	proxyFlagOutput            string
)

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringVarP(&proxyFlagProxyCidr, "cidr", "c", "", "cidr proxy to scan e.g. 104.16.0.0/24")
	proxyCmd.Flags().StringVar(&proxyFlagProxyHost, "proxy", "", "proxy without port")
	proxyCmd.Flags().StringVarP(&proxyFlagProxyHostFilename, "filename", "f", "", "proxy filename without port")
	proxyCmd.Flags().IntVarP(&proxyFlagProxyPort, "port", "p", 80, "proxy port")
	proxyCmd.Flags().StringVarP(&proxyFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	proxyCmd.Flags().StringVarP(&proxyFlagMethod, "method", "M", "GET", "request method")
	proxyCmd.Flags().StringVar(&proxyFlagTarget, "target", "", "target server (response must be 101)")
	proxyCmd.Flags().StringVar(&proxyFlagPath, "path", "/", "request path")
	proxyCmd.Flags().StringVar(&proxyFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	proxyCmd.Flags().StringVar(&proxyFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught proxy")
	proxyCmd.Flags().IntVar(&proxyFlagTimeout, "timeout", 3, "handshake timeout")
	proxyCmd.Flags().StringVarP(&proxyFlagOutput, "output", "o", "", "output result")

	proxyFlagMethod = strings.ToUpper(proxyFlagMethod)
}

func scanProxy(c *queuescanner.Ctx, host string) {

	regexpIsIP := regexp.MustCompile(`\d+$`)
	bug := proxyFlagBug
	if bug == "" {
		if regexpIsIP.MatchString(host) {
			bug = proxyFlagTarget
		} else {
			bug = host
		}
	}

	if proxyFlagPath == "/" {
		bug = proxyFlagTarget
	}

	proxyHostPort := net.JoinHostPort(host, fmt.Sprintf("%d", proxyFlagProxyPort))

	conn, err := net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	go func() {
		payload := getScanProxyPayloadDecoded(bug)
		payload = strings.ReplaceAll(payload, "[host]", proxyFlagTarget)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		_, err = conn.Write([]byte(payload))
		if err != nil {
			chanResult <- false
			return
		}

		scanner := bufio.NewScanner(conn)
		isPrefix := true
		responseLines := make([]string, 0)

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

		if len(responseLines) == 0 {
			chanResult <- false
			return
		}

		if strings.Contains(responseLines[0], " 302 ") {
			chanResult <- true
			return
		}

		resultString := fmt.Sprintf("%-32s %s", proxyHostPort, strings.Join(responseLines, " -- "))
		c.ScanSuccess(resultString)
		c.Log(resultString)

		chanResult <- true
	}()

	select {
	case <-chanResult:
	case <-ctxResultTimeout.Done():
	}
}

func getScanProxyPayloadDecoded(bug ...string) string {
	payload := proxyFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", proxyFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", proxyFlagPath)
	payload = strings.ReplaceAll(payload, "[protocol]", proxyFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanProxy(cmd *cobra.Command, args []string) {
	var proxyHosts []string

	if proxyFlagProxyHost != "" {
		proxyHosts = append(proxyHosts, proxyFlagProxyHost)
	}

	if proxyFlagProxyHostFilename != "" {
		lines, err := ReadFile(proxyFlagProxyHostFilename)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, lines...)
	}

	if proxyFlagProxyCidr != "" {
		cidrHosts, err := IPsFromCIDR(proxyFlagProxyCidr)
		if err != nil {
			fatal(err)
		}
		proxyHosts = append(proxyHosts, cidrHosts...)
	}

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanProxy)
	queueScanner.Add(proxyHosts)
	fmt.Printf("%s\n\n", getScanProxyPayloadDecoded())
	queueScanner.SetOutputFile(proxyFlagOutput)
	queueScanner.SetPrintInterval(globalFlagPrintInterval)
	queueScanner.Start()
}
