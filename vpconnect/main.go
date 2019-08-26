// vpconnect is a program to generate strongswan config for either a site-2-site vpn
// or a virtual user vpn. It will then manage the correct iptables rules, route tables.
// And make sure ipsec is started, manage reloads, restarts and shutdowns.
// It will send any messages to CloudWatch Logs.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var debug = false

// setDebugLevel will check the DEBUG env var and if set try and convert it to
// an bool. If it fails to convert we will exit(1).
func setDebugLevel() {
	val := strings.ToLower(removeSpaces(os.Getenv("DEBUG")))
	if val == "" {
		val = "false"
	}

	// Convert debug env var to bool. If it fails exit(1).
	d, err := strconv.ParseBool(val)
	if err != nil {
		print(&msg{Message: fmt.Sprintf("DEBUG env var set, but couldn't be converted to bool. Error %s", err.Error()), LogLevel: "error"})
		exit(1)
	}

	debug = d
	print(&msg{Message: fmt.Sprintf("init(): Debug var set to %t", debug), LogLevel: "info"})
}

// main contains the main flow of the vpconnect program.
func main() {
	print(&msg{Message: "main(): Starting program", LogLevel: "info"})
	setDebugLevel()

	// Create new vpconnect.
	v, err := new()
	if err != nil {
		print(&msg{Message: err.Error(), LogLevel: "error"})
		exit(1)
	}

	// Create the iptable rules and DNS updater.
	if err := v.createRules(); err != nil {
		print(&msg{Message: err.Error(), LogLevel: "error"})
		exit(1)
	}

	// Don't start IPSec if config says no IPSec.
	if !v.NoIpsec {
		// Generate the IPSec config files.
		if err := v.create(); err != nil {
			print(&msg{Message: err.Error(), LogLevel: "error"})
			exit(1)
		}

		// Start ipsec and checker.
		if err := v.start(); err != nil {
			print(&msg{Message: err.Error(), LogLevel: "error"})
			exit(1)
		}
		v.ipsec()
	}

	// Wait until we receive an exit signal.
	v.wait()
}
