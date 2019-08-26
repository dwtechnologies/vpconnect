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

	// Don't add IPSec specific rules if we started with no IPSec.
	if !v.NoIpsec {
		// Do not do any POSTROUTING on ipsec packets.
		list = append(list, []string{"-t", "nat", "-I", "POSTROUTING", "1", "-m", "policy", "--pol", "ipsec", "--dir", "out", "-j", "ACCEPT"})

		// Loop over all connections and add rules for all remotes.
		for _, conn := range v.Connections {
			for _, remote := range conn.Remotes {
				list = append(list, []string{"-A", "INPUT", "-s", fmt.Sprintf("%s/32", remote.Ip), "-p", "udp", "--dport", "500", "-i", "eth1", "-j", "ACCEPT"})
				list = append(list, []string{"-A", "INPUT", "-s", fmt.Sprintf("%s/32", remote.Ip), "-p", "udp", "--dport", "4500", "-i", "eth1", "-j", "ACCEPT"})
			}
		}
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
func (v *vpconnect) addIptableRule(r *parsedRule) error {
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

	// For all other protocols we will use destination port.
	default:
		list = append(list, []string{"-A", "FORWARD", "-s", r.from, "-d", r.to, "-p", r.protocol, "--dport", strconv.Itoa(r.port), "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-A", "POSTROUTING", "-s", r.from, "-d", r.to, "-p", r.protocol, "--dport", strconv.Itoa(r.port), "-o", "eth1", "-j", "MASQUERADE"})
		}
		if r.portforward != 0 {
			list = append(list, []string{"-t", "nat", "-A", "PREROUTING", "-s", r.from, "-p", r.protocol, "--dport", strconv.Itoa(r.portforward), "-i", "eth1", "-j", "DNAT", "--to", fmt.Sprintf("%s:%d", removeNetmask(r.to), r.port)})
		}
	}

	printRule("adding", r)

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
func (v *vpconnect) deleteIptableRule(r *parsedRule) error {
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

	// For all other protocols we will use destination port.
	default:
		list = append(list, []string{"-D", "FORWARD", "-s", r.from, "-d", r.to, "--dport", strconv.Itoa(r.port), "-p", r.protocol, "-i", "eth1", "-j", "ACCEPT"})
		if r.masquerade {
			list = append(list, []string{"-t", "nat", "-D", "POSTROUTING", "-s", r.from, "-d", r.to, "--dport", strconv.Itoa(r.port), "-p", r.protocol, "-o", "eth1", "-j", "MASQUERADE"})
		}
		if r.portforward != 0 {
			list = append(list, []string{"-t", "nat", "-D", "PREROUTING", "-s", r.from, "-p", r.protocol, "--dport", strconv.Itoa(r.portforward), "-i", "eth1", "-j", "DNAT", "--to", fmt.Sprintf("%s:%d", removeNetmask(r.to), r.port)})
		}
	}

	printRule("deleting", r)

	// Execute the commands.
	for _, args := range list {
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("v.deleteIptableRule(): command 'iptables %s' failed. Error %s", strings.Join(args, " "), err.Error())
		}
	}

	return nil
}
