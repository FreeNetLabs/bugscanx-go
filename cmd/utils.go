package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
)

var ipRegex = regexp.MustCompile(`\d+$`)

func ReadFile(filename string) ([]string, error) {
	var reader io.Reader

	if filename == "" || filename == "-" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return nil, fmt.Errorf("error checking stdin: %w", err)
		}

		if (stat.Mode() & os.ModeCharDevice) == 0 {
			reader = os.Stdin
		} else {
			return nil, fmt.Errorf("no input provided: use -f flag or pipe data via stdin")
		}
	} else {
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}

	var lines []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func ipInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IPsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for currentIP := ip.Mask(ipnet.Mask); ipnet.Contains(currentIP); ipInc(currentIP) {
		ips = append(ips, currentIP.String())
	}
	if len(ips) <= 1 {
		return ips, nil
	}

	return ips[1 : len(ips)-1], nil
}

func fatal(err error) {
	fmt.Println(err.Error())
	os.Exit(1)
}
