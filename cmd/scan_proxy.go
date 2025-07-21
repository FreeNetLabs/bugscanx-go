package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ayanrajpoot10/bugscanx-go/pkg/queuescanner"
)

var scanProxyCmd = &cobra.Command{
	Use:     "proxy",
	Short:   "Scan using a proxy with payload to a target.",
	Example: "  bugscanx-go proxy --cidr 192.168.1.0/24 --target example.com\n  bugscanx-go proxy --filename proxy.txt --target example.com --payload test",
	Run:     runScanProxy,
}

var (
	scanProxyFlagProxyCidr         string
	scanProxyFlagProxyHost         string
	scanProxyFlagProxyHostFilename string
	scanProxyFlagProxyPort         int
	scanProxyFlagBug               string
	scanProxyFlagMethod            string
	scanProxyFlagTarget            string
	scanProxyFlagPath              string
	scanProxyFlagProtocol          string
	scanProxyFlagPayload           string
	scanProxyFlagTimeout           int
	scanProxyFlagOutput            string
)

func init() {
	rootCmd.AddCommand(scanProxyCmd)

	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyCidr, "cidr", "c", "", "cidr proxy to scan e.g. 127.0.0.1/32")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProxyHost, "proxy", "", "proxy without port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyHostFilename, "filename", "f", "", "proxy filename without port")
	scanProxyCmd.Flags().IntVarP(&scanProxyFlagProxyPort, "port", "p", 80, "proxy port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagMethod, "method", "M", "GET", "request method")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagTarget, "target", "", "target server (response must be 101)")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagPath, "path", "/", "request path")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanProxyCmd.Flags().StringVar(
		&scanProxyFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught proxy",
	)
	scanProxyCmd.Flags().IntVar(&scanProxyFlagTimeout, "timeout", 3, "handshake timeout")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagOutput, "output", "o", "", "output result")

	scanProxyFlagMethod = strings.ToUpper(scanProxyFlagMethod)
}

type scanProxyRequest struct {
	ProxyHost string
	ProxyPort int
	Bug       string
	Method    string
	Target    string
	Payload   string
}

func scanProxy(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanProxyRequest)
	if !ok {
		return
	}

	var conn net.Conn
	var err error
	dnsErr := new(net.DNSError)

	proxyHostPort := fmt.Sprintf("%s:%d", req.ProxyHost, req.ProxyPort)
	dialCount := 0

	for {
		dialCount++
		if dialCount > 3 {
			return
		}
		conn, err = net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
		if err != nil {
			if errors.As(err, &dnsErr) {
				return
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
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

	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	go func() {
		payload := req.Payload
		payload = strings.ReplaceAll(payload, "[host]", req.Target)
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
	payload := scanProxyFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", scanProxyFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", scanProxyFlagPath)
	payload = strings.ReplaceAll(payload, "[protocol]", scanProxyFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanProxy(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	if scanProxyFlagProxyHost != "" {
		proxyHostList[scanProxyFlagProxyHost] = true
	}

	if scanProxyFlagProxyHostFilename != "" {
		lines, err := ReadLinesFromFile(scanProxyFlagProxyHostFilename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		for _, proxyHost := range lines {
			proxyHostList[proxyHost] = true
		}
	}

	if scanProxyFlagProxyCidr != "" {
		proxyHostListFromCidr, err := ipListFromCidr(scanProxyFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting ip list from cidr error: %s", err.Error())
			os.Exit(1)
		}

		for _, proxyHost := range proxyHostListFromCidr {
			proxyHostList[proxyHost] = true
		}
	}

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanProxy)
	regexpIsIP := regexp.MustCompile(`\d+$`)

	for proxyHost := range proxyHostList {
		bug := scanProxyFlagBug

		if bug == "" {
			if regexpIsIP.MatchString(proxyHost) {
				bug = scanProxyFlagTarget
			} else {
				bug = proxyHost
			}
		}

		if scanProxyFlagPath == "/" {
			bug = scanProxyFlagTarget
		}

		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, scanProxyFlagProxyPort, scanProxyFlagTarget),
			Data: &scanProxyRequest{
				ProxyHost: proxyHost,
				ProxyPort: scanProxyFlagProxyPort,
				Bug:       bug,
				Method:    scanProxyFlagMethod,
				Target:    scanProxyFlagTarget,
				Payload:   getScanProxyPayloadDecoded(bug),
			},
		})
	}

	fmt.Printf("%s\n\n", getScanProxyPayloadDecoded())

	queueScanner.SetOutputFile(scanProxyFlagOutput)
	queueScanner.Start()
}
