package cmd

import (
	"bufio"
	"net"
	"os"
)

// ReadLinesFromFile reads a text file line by line and returns a slice of non-empty lines.
//
// This function opens the specified file, reads it line by line using a buffered scanner,
// and filters out empty lines. It's commonly used to read domain lists, IP lists, or
// other input files for scanning operations.
//
// Parameters:
//   - filename: The path to the file to be read
//
// Returns:
//   - []string: A slice containing all non-empty lines from the file
//   - error: Any error that occurred during file operations
//
// Example usage:
//
//	domains, err := ReadLinesFromFile("domains.txt")
//	if err != nil {
//		log.Fatal(err)
//	}
//	// Process domains...
func ReadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
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

// ipInc increments an IP address by one, handling carry-over for each octet.
//
// This function treats the IP address as a big-endian integer and increments it.
// It starts from the least significant byte and propagates carries to more
// significant bytes when overflow occurs. This is used internally for generating
// IP ranges from CIDR notation.
//
// Parameters:
//   - ip: The IP address to increment (modified in-place)
//
// Note: This function modifies the input IP address directly.
func ipInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipListFromCidr generates a list of IP addresses from a CIDR notation string.
//
// This function takes a CIDR block (e.g., "192.168.1.0/24") and generates all
// valid host IP addresses within that range, excluding the network and broadcast
// addresses. It's useful for generating target lists for proxy scanning or
// network reconnaissance.
//
// Parameters:
//   - cidr: A string representing the CIDR block (e.g., "10.0.0.0/8", "192.168.1.0/24")
//
// Returns:
//   - []string: A slice of IP addresses as strings, excluding network and broadcast addresses
//   - error: Any error that occurred during CIDR parsing
//
// Example usage:
//
//	ips, err := ipListFromCidr("192.168.1.0/24")
//	if err != nil {
//		log.Fatal(err)
//	}
//	// ips contains ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
//
// Note: For single IP addresses (/32), the function returns the IP without exclusions.
func ipListFromCidr(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ipInc(ip) {
		ipString := ip.String()
		ips = append(ips, ipString)
	}
	if len(ips) <= 1 {
		return ips, nil
	}

	// Exclude network and broadcast addresses for ranges larger than /32
	return ips[1 : len(ips)-1], nil
}
