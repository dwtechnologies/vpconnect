package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

var iptablesInitArgs = [][]string{
	[]string{"-P", "INPUT", "DROP"},    // Set default policy on INPUT to DROP.
	[]string{"-P", "FORWARD", "DROP"},  // Set default policy on FORWARD to DROP.
	[]string{"-P", "OUTPUT", "ACCEPT"}, // Set default policy on OUTPUT to ACCEPT.
	[]string{"-t", "nat", "-F"},        // Flush nat table.
	[]string{"-t", "nat", "-X"},        // Delete custom nat.
	[]string{"-t", "mangle", "-F"},     // Flush mangle table.
	[]string{"-t", "mangle", "-X"},     // Delete custom mangle.
	[]string{"-F"},                     // Flush filter table.
	[]string{"-X"},                     // Delete custom filter.

	// Don't do any POSTROUTING on ipsec packets.
	[]string{"-t", "nat", "-I", "POSTROUTING", "1", "-m", "policy", "--pol", "ipsec", "--dir", "out", "-j", "ACCEPT"},
	// Accept established and related on INPUT chain.
	[]string{"-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	// Accept established and related on FORWARD chain.
	[]string{"-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	// Accept all on loopback in INPUT chain.
	[]string{"-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
	// Log all new packets with log level 6 on INPUT chain.
	[]string{"-A", "INPUT", "-m", "state", "--state", "NEW", "-j", "LOG", "--log-level", "6", "--log-prefix", "[ACCEPT:INPUT] "},
	// Log all new packets with log level 6 on FORWARD chain.
	[]string{"-A", "FORWARD", "-m", "state", "--state", "NEW", "-j", "LOG", "--log-level", "6", "--log-prefix", "[ACCEPT:FORWARD] "},
}

// initIptables will create a sensible default iptables setup. With policies that DROP all
// packets on INPUT and FORWARD chain by default.
// Returns error.
func (v *vpconnect) initIptables() error {
	print(&msg{Message: "v.initIptables(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.initIptables(): Returning", LogLevel: "debug"})

	// Create list and add primary and secondary IP to the list.
	list := iptablesInitArgs
	for _, ip := range v.right.remoteIPs {
		list = append(list, []string{"-A", "INPUT", "-s", fmt.Sprintf("%s/32", ip), "-p", "udp", "--dport", "500", "-i", "eth1", "-j", "ACCEPT"})
		list = append(list, []string{"-A", "INPUT", "-s", fmt.Sprintf("%s/32", ip), "-p", "udp", "--dport", "4500", "-i", "eth1", "-j", "ACCEPT"})
	}

	// Set initial policies.
	for _, args := range list {
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("v.initIptables(): command 'iptables %s' failed. Error %s", args, err.Error())
		}

		print(&msg{Message: fmt.Sprintf("v.initIptables(): Command 'iptables %s' successfully executed", strings.Join(args, " ")), LogLevel: "debug"})
	}

	print(&msg{Message: "v.initIptables(): Basic ruleset created", LogLevel: "info"})
	return nil
}

// addIptableRule will add an iptable rule with the variables contained in r.
// Returns error.
func (v *vpconnect) addIptableRule(r *rule) error {
	print(&msg{Message: "v.addIptableRule(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.addIptableRule(): Returning", LogLevel: "debug"})
	list := [][]string{}

	switch {
	// If protocol is all, icmp or port is -1 allow all ports.
	case r.protocol == "all" || r.protocol == "icmp" || r.port == -1:
		list = append(list, []string{"-A", "FORWARD", "-s", r.from, "-d", r.to, "-p", r.protocol, "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-A", "POSTROUTING", "-s", r.from, "-d", r.to, "-p", r.protocol, "-o", "eth1", "-j", "MASQUERADE"})
		}

		print(&msg{Message: fmt.Sprintf("v.addIptableRule(): Adding rule for %s to %s/%s with masquerading set to %t", r.from, r.protocol, r.to, r.masquerade), LogLevel: "info"})

	// For all other protocols we will use destination port.
	default:
		list = append(list, []string{"-A", "FORWARD", "-s", r.from, "-d", r.to, "-p", r.protocol, "--dport", strconv.Itoa(r.port), "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-A", "POSTROUTING", "-s", r.from, "-d", r.to, "-p", r.protocol, "--dport", strconv.Itoa(r.port), "-o", "eth1", "-j", "MASQUERADE"})
		}

		print(&msg{Message: fmt.Sprintf("v.addIptableRule(): Adding rule for %s to %s/%s:%d with masquerading set to %t", r.from, r.protocol, r.to, r.port, r.masquerade), LogLevel: "info"})
	}

	// Execute the commands.
	for _, args := range list {
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("v.addIptableRule(): command 'iptables %s' failed. Error %s", strings.Join(args, " "), err.Error())
		}
	}

	return nil
}

// deleteIptableRule will delete an iptable rule with the variables contained in r.
// Returns error.
func (v *vpconnect) deleteIptableRule(r *rule) error {
	print(&msg{Message: "v.deleteIptableRule(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.deleteIptableRule(): Returning", LogLevel: "debug"})
	list := [][]string{}

	switch {
	// If protocol is all, icmp or port is -1 allow all ports.
	case r.protocol == "all" || r.protocol == "icmp" || r.port == -1:
		list = append(list, []string{"-D", "FORWARD", "-s", r.from, "-d", r.to, "-p", r.protocol, "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-D", "POSTROUTING", "-s", r.from, "-d", r.to, "-p", r.protocol, "-o", "eth1", "-j", "MASQUERADE"})
		}

		print(&msg{Message: fmt.Sprintf("v.deleteIptableRule(): Deleting rule for %s to %s/%s with masquerading set to %t", r.from, r.protocol, r.to, r.masquerade), LogLevel: "info"})

	// For all other protocols we will use destination port.
	default:
		list = append(list, []string{"-D", "FORWARD", "-s", r.from, "-d", r.to, "--dport", strconv.Itoa(r.port), "-p", r.protocol, "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-D", "POSTROUTING", "-s", r.from, "-d", r.to, "--dport", strconv.Itoa(r.port), "-p", r.protocol, "-o", "eth1", "-j", "MASQUERADE"})
		}

		print(&msg{Message: fmt.Sprintf("v.deleteIptableRule(): Deleting rule for %s to %s/%s:%d with masquerading set to %t", r.from, r.protocol, r.to, r.port, r.masquerade), LogLevel: "info"})
	}

	// Execute the commands.
	for _, args := range list {
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("v.deleteIptableRule(): command 'iptables %s' failed. Error %s", strings.Join(args, " "), err.Error())
		}
	}

	return nil
}
