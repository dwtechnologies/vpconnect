package main

import (
	"fmt"
	"net"
)

// getCIDR takes input and check if it's a valid CIDR, IP or
// hostname and returns the IPs as a slice of strings.
// The steps are as follows:
// - Checks if input is a valid CIDR, returns if true.
// - Checks if input is a valid IP, returns if true with appended /32 annotation.
// - Tries to do a hostname lookup, if successfull returns with appended /32 annotation,
//   otherwise returns error.
// Returns []string and error.
func getCIDR(input string) ([]string, error) {
	print(&msg{Message: "getCIDR(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "getCIDR(): Returning", LogLevel: "debug"})

	switch {
	// Just return the input as a slice if
	// it's a valid CIDR annotation.
	case isValidCIDR(input) == true:
		return []string{input}, nil

		// Return as a /32 CIDR annotation if it's a valid IP.
	case isValidIP(input) == true:
		return []string{fmt.Sprintf("%s/32", input)}, nil
	}

	// Return the IP slices as /32 CIDR annotation if
	// hostname resolve works.
	return dnsLookup(input)
}

// isValidCIDR returns true if cidr is a valid CIDR.
// Returns bool.
func isValidCIDR(cidr string) bool {
	print(&msg{Message: "isValidCIDR(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "isValidCIDR(): Returning", LogLevel: "debug"})

	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return false
	}
	return true
}

// isValidIP returns true if ip is a valid IP address.
// Returns bool.
func isValidIP(ip string) bool {
	print(&msg{Message: "isValidIP(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "isValidIP(): Returning", LogLevel: "debug"})

	if check := net.ParseIP(ip); check == nil {
		return false
	}
	return true
}

// dnsLookup does DNS lookup on the host and returns the
// ip addresses it's resolved to. Returns the IP in
// CIDR /32 annotation slice of strings.
// Returns []string and error.
func dnsLookup(host string) ([]string, error) {
	print(&msg{Message: "dnsLookup(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "dnsLookup(): Returning", LogLevel: "debug"})

	ret := []string{}

	ips, err := net.LookupIP(host)
	if err != nil {
		return []string{}, fmt.Errorf("dnsLookup(): Couldn't do hostname lookup on %s. Error %s", host, err.Error())
	}

	// Get all IPs and append them in CIDR /32 annotation to ret.
	for _, ip := range ips {
		ret = append(ret, fmt.Sprintf("%s/32", ip.String()))
	}

	return ret, nil
}
