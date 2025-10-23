package cmd

import (
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

var directCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection to targets.",
	Run:   scanDirectRun,
}

var (
	directFlagFilename       string
	directFlagPort           string
	directFlagOutput         string
	directFlagHideLocation   string
	directFlagMethod         string
	directFlagTimeoutConnect int
	directFlagTimeoutRequest int
	directFlagTimeoutDNS     int
)

func init() {
	rootCmd.AddCommand(directCmd)

	directCmd.Flags().StringVarP(&directFlagFilename, "filename", "f", "", "domain list filename")
	directCmd.Flags().StringVarP(&directFlagPort, "port", "p", "80", "port(s) to scan - single (80) or multiple comma-separated (80,443,8080)")
	directCmd.Flags().StringVarP(&directFlagOutput, "output", "o", "", "output result")
	directCmd.Flags().StringVarP(&directFlagMethod, "method", "m", "HEAD", "HTTP method to use")
	directCmd.Flags().StringVar(&directFlagHideLocation, "skip", "https://jio.com/BalanceExhaust", "skip results with this Location header")
	directCmd.Flags().IntVar(&directFlagTimeoutConnect, "timeout-connect", 5, "TCP connect timeout in seconds")
	directCmd.Flags().IntVar(&directFlagTimeoutRequest, "timeout-request", 10, "Overall request timeout in seconds")
	directCmd.Flags().IntVar(&directFlagTimeoutDNS, "timeout-dns", 5, "DNS lookup timeout in seconds")
}

func parsePorts(portSpec string) ([]string, error) {
	var ports []string

	parts := strings.Split(portSpec, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", part)
		}

		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port must be between 1 and 65535: %d", port)
		}

		ports = append(ports, part)
	}

	return ports, nil
}

func extractHTTPHeaders(response string) (statusCode int, server string, location string) {
	lines := strings.Split(response, "\n")

	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				statusCode = code
			}
		}
	}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[9:])
		}
	}

	return statusCode, server, location
}

func scanDirect(c *queuescanner.Ctx, host string) {
	ports, err := parsePorts(directFlagPort)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(directFlagTimeoutDNS)*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return
	}

	ip := ips[0]
	ipStr := ip.String()

	for _, port := range ports {
		useTLS := false
		commonHTTPSPorts := []string{"443", "8443", "9443", "10443"}
		for _, httpsPort := range commonHTTPSPorts {
			if port == httpsPort {
				useTLS = true
				break
			}
		}

		address := fmt.Sprintf("%s:%s", ipStr, port)
		network := "tcp4"

		dialer := &net.Dialer{
			Timeout: time.Duration(directFlagTimeoutConnect) * time.Second,
		}

		var conn net.Conn
		if useTLS {
			conn, err = tls.DialWithDialer(dialer, network, address, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			})
		} else {
			conn, err = dialer.Dial(network, address)
		}
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(time.Duration(directFlagTimeoutRequest) * time.Second))

		method := directFlagMethod
		if method == "" {
			method = "HEAD"
		}

		httpRequest := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\nUser-Agent: bugscanx-go/1.0\r\nConnection: close\r\n\r\n", method, host)

		_, err = conn.Write([]byte(httpRequest))
		if err != nil {
			conn.Close()
			continue
		}

		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		conn.Close()

		if err != nil {
			continue
		}

		response := string(buffer[:n])
		statusCode, server, location := extractHTTPHeaders(response)

		if directFlagHideLocation != "" && location == directFlagHideLocation {
			continue
		}

		hostWithPort := fmt.Sprintf("%s:%s", host, port)
		formatted := fmt.Sprintf("%-15s  %-3d   %-16s    %s", ipStr, statusCode, server, hostWithPort)

		c.ScanSuccess(formatted)
		c.Log(formatted)
	}
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	hosts, err := ReadFile(directFlagFilename)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "IP Address", "Code", "Server", "Host")
	fmt.Printf("%-15s  %-3s  %-16s    %s\n", "----------", "----", "------", "----")

	queueScanner := queuescanner.NewQueueScanner(globalFlagThreads, scanDirect)
	queueScanner.Add(hosts)
	queueScanner.SetOutputFile(directFlagOutput)
	queueScanner.SetPrintInterval(globalFlagPrintInterval)
	queueScanner.Start()
}
