// Package main provides the entry point for the bugscanx-go application.
//
// BugscanX-Go is a powerful network security scanner designed for penetration testing
// and security assessment. It provides multiple scanning modes including direct connection
// scanning, proxy scanning, SNI enumeration, CDN SSL analysis, and ping functionality.
//
// The application supports concurrent scanning with configurable thread pools,
// making it suitable for large-scale network reconnaissance and vulnerability assessment.
//
// Usage:
//
//	bugscanx-go direct -f hosts.txt -o results.txt
//	bugscanx-go ping -f domains.txt --port 443
//	bugscanx-go sni -f domains.txt --deep 2
//	bugscanx-go proxy --cidr 192.168.1.0/24 --target example.com
//	bugscanx-go cdn-ssl --filename proxies.txt --target ssl-site.com
package main

import (
	"github.com/ayanrajpoot10/bugscanx-go/cmd"
)

// main is the entry point of the bugscanx-go application.
// It initializes the command-line interface and delegates execution
// to the cmd package's Execute function.
func main() {
	cmd.Execute()
}
