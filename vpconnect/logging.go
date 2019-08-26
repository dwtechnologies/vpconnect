package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// msg is used by the print function to print a message to stdout.
// That in turn can be sent to CloudWatch Logs via the awslogs
// docker driver.
type msg struct {
	Message  string `json:"message"`
	LogLevel string `json:"loglevel"`
	Time     string `json:"time"`
}

// print will print the msg in a JSON fashion. This will be sent to stdout and
// will be handled by the awslogs docker driver and sent to CloudWatch Logs.
// Any message with LogLevel debug will be ignored if Env var DEBUG isn't set
// to true (default is false).
// Valid loglevels are: debug, info, warning, error
func print(m *msg) {
	if m.LogLevel == "debug" && !debug {
		return
	}

	// Check that LogLevel is valid. Otherwise default to info and print a warning about a wrong LogLevel
	// being sent to the logger.
	if m.LogLevel != "debug" && m.LogLevel != "info" && m.LogLevel != "warning" && m.LogLevel != "error" {
		print(&msg{
			Message: fmt.Sprintf(
				"print(): Got an invalid LogLevel. Expected debug, info, warning or error but got %s. Will set LogLevel to info",
				m.LogLevel,
			),
			LogLevel: "warning"})

		// Set the LogLevel to info.
		m.LogLevel = "info"
	}

	m.Time = time.Now().UTC().Format("2006-01-02 15:04:05") // Add time in UTC.
	out, _ := json.Marshal(m)
	fmt.Println(string(out))
}

// printRule prints the specific message for rule based on msgType
// and the content of rule.
func printRule(t string, r *parsedRule) {
	action := "Adding"
	if t == "delete" {
		action = "Deleting"
	}

	m := fmt.Sprintf("printRule(): %s rule for %s/%d from %s to %s", action, r.protocol, r.port, r.from, r.to)
	switch {
	// All protocols.
	case r.masquerade && r.protocol == "all":
		m = fmt.Sprintf("printRule(): %s rule for %s to %s with masquerading", action, r.from, r.to)

	case r.protocol == "all":
		m = fmt.Sprintf("printRule(): %s rule for %s to %s", action, r.from, r.to)

	// All ports.
	case r.masquerade && r.port == -1:
		m = fmt.Sprintf("printRule(): %s rule for %s from %s to %s with masquerading", action, r.protocol, r.from, r.to)

	case r.port == -1:
		m = fmt.Sprintf("printRule(): %s rule for %s from %s to %s", action, r.protocol, r.from, r.to)

	// ICMP messages.
	case r.masquerade && r.protocol == "icmp":
		m = fmt.Sprintf("printRule(): %s rule for %s from %s to %s with masquerading", action, r.protocol, r.from, r.to)

	case r.protocol == "icmp":
		m = fmt.Sprintf("printRule(): %s rule for %s from %s to %s", action, r.protocol, r.from, r.to)

	// Portforward.
	case r.masquerade && r.portforward != 0:
		m = fmt.Sprintf("printRule(): %s rule for %s to %s/%s:%d with masquerading and portforwarding from %d", action, r.from, r.protocol, r.to, r.port, r.portforward)

	// Masq
	case r.masquerade:
		m = fmt.Sprintf("printRule(): %s rule for %s to %s/%s:%d with masquerading", action, r.from, r.protocol, r.to, r.port)
	}

	print(&msg{Message: m, LogLevel: "info"})
}
