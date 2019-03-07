package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// createRules will create the interval ticker and create the iptables rules.
// It will check that the iptables rules are correct based on the set interval.
// Return error.
func (v *vpconnect) createRules() error {
	print(&msg{Message: "v.createRules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.createRules(): Returning", LogLevel: "debug"})

	// Create initial iptable rules.
	if err := v.initIptables(); err != nil {
		return err
	}

	// Create the check ticker, this ticker will be used to check
	// that the correct iptable rules are set.
	if err := v.createTicker(); err != nil {
		return err
	}

	// Check iptable rules in a separate go-routine and update
	// them based on the set interval.
	go func() {
		for {
			// Create the rules and update them based on the set interval.
			if err := v.rules(); err != nil {
				print(&msg{Message: err.Error(), LogLevel: "error"})
				v.stopping <- true
			}

			// Wait for the interval to expire.
			<-v.check.C
		}
	}()

	return nil
}

// createTicker creates the v.check ticker that is used for updating hosts and ips based on the
// check rate set by the CHECK_INTERVAL env variable. If not set it will default to 300 (seconds).
// Returns error.
func (v *vpconnect) createTicker() error {
	print(&msg{Message: "v.createTicker(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.createTicker(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.createTicker(): Getting ticker interval", LogLevel: "debug"})
	interval := os.Getenv("CHECK_INTERVAL")
	dur := time.Duration(0)

	switch {
	case interval != "":
		i, err := strconv.Atoi(interval)
		if err != nil {
			return fmt.Errorf("v.createTicker(): CHECK_INTERVAL set (%s) but couldn't be converted to integer. Error %s", interval, err.Error())
		}

		// Treat 0 as not set and default to 300.
		if i == 0 {
			i = 300
		}
		dur = time.Duration(i) * time.Second

	default:
		print(&msg{Message: "v.createTicker(): CHECK_INTERVAL not set. Defaulting to 300 seconds", LogLevel: "debug"})
		dur = time.Duration(300) * time.Second
	}

	// Create a channel that triggers every dur seconds.
	print(&msg{Message: fmt.Sprintf("v.createTicker(): Creating ticker with an interval of %f seconds", dur.Seconds()), LogLevel: "info"})
	v.check = time.NewTicker(dur)

	return nil
}

// rules will generate all the necessary rules to do a proper iptables setup.
// it will sort the result and apply it to the desiredRules key and then add / delete
// new and old rules from iptables accordingly.
func (v *vpconnect) rules() error {
	print(&msg{Message: "v.rules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.rules(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.rules(): Checking/updating iptable rules", LogLevel: "info"})
	// Generate rules form importedRules and to DNS lookup.
	if err := v.generateRules(); err != nil {
		return err
	}

	// Get keys that should be added and deleted.
	addKeys, deleteKeys := v.compareDesiredAndActiveRules()

	// Delete keys.
	for _, id := range deleteKeys {
		if err := v.deleteIptableRule(v.activeRules[id]); err != nil {
			return err
		}
	}

	// Add keys.
	for _, id := range addKeys {
		if err := v.addIptableRule(v.desiredRules[id]); err != nil {
			return err
		}
	}

	// Update desired to active.
	v.activeRules = v.desiredRules

	return nil
}

// compareDesiredAndActiveRules will compare desired and active rules.
// If a rule is desired, but not active it will be execute the iptables
// command accordingly to add it. If it's active but not desired it will
// be removed accordingly. Returns rule keys to add and rule keys to delete.
func (v *vpconnect) compareDesiredAndActiveRules() ([]int, []int) {
	print(&msg{Message: "v.compareDesiredAndActiveRules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.compareDesiredAndActiveRules(): Returning", LogLevel: "debug"})

	// Key ids for rules that match, should be added or deleted.
	sameKeys := []int{}
	deleteKeys := []int{}
	addKeys := []int{}

	// Loop through all desired rules and compare them to the active
	// ones. If the rule isn't found in the active rules slice add
	// the desiredRules slice key to the addKeys int slice.
	for desiredKey, desiredState := range v.desiredRules {
		// state == 1, key will be added.
		// state  == 0, key already exists.
		state := 1
		key := desiredKey

		for activeKey, activeState := range v.activeRules {
			// If the desired rules is found in the active list
			// add the active rule key to the sameKeys int slice.
			// And set the state to 0. To indicate it shouldn't
			// be added.
			if v.compareRules(desiredState, activeState) {
				state = 0
				key = activeKey
			}
		}

		switch state {
		// Key already exists, add to the sameKeys int slice.
		case 0:
			sameKeys = append(sameKeys, key)
		// Key doesn't exist, add to the addKeys int slice.
		case 1:
			addKeys = append(addKeys, key)
		}
	}

	// If the length os sameKeys and v.activeRules aren't the same
	// there is keys thats need to be deleted. So go through them.
	//TODO: This could be optimized. It's not the fastest solution.
	if len(sameKeys) != len(v.activeRules) {
		// Loop through all activeKeys and see if the key exists
		// there or not. If it doesn't add the key to deleteKeys
		// slice of ints.
		for activeKey := range v.activeRules {
			for _, sameKey := range sameKeys {
				if activeKey != sameKey {
					deleteKeys = append(deleteKeys, activeKey)
				}
			}
		}
	}

	return addKeys, deleteKeys
}

// comparRules compares r1 and r2 with each other and returns
// true if r1 and r2 are the same. Otherwise returns false.
// Returns bool.
func (*vpconnect) compareRules(r1 *parsedRule, r2 *parsedRule) bool {
	print(&msg{Message: "v.compareRules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.compareRules(): Returning", LogLevel: "debug"})

	switch {
	case r1.from != r2.from:
		return false
	case r1.to != r2.to:
		return false
	case r1.port != r2.port:
		return false
	case r1.protocol != r2.protocol:
		return false
	case r1.masquerade != r2.masquerade:
		return false
	}
	return true
}

// generateRules will generate all the necessary rules to do a proper iptables setup.
// And set the results to the v.desiredRules key.
// Returns error.
func (v *vpconnect) generateRules() error {
	print(&msg{Message: "v.generateRules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRules(): Returning", LogLevel: "debug"})

	// Make a channel for sending rules so we can append them
	// to a the desired slice of rules.
	c := make(chan *parsedRule)
	rules := []*parsedRule{}

	// Append all rules to the rules slice.
	go func() {
		for r := range c {
			rules = append(rules, r)
		}
	}()

	// Loop through all the imported rules.
	wg := &sync.WaitGroup{}
	for _, r := range v.Rules {
		currentRule := r
		wg.Add(1)
		go v.generateRulesFrom(c, wg, currentRule)
	}
	wg.Wait()
	close(c)

	// Check that we didn't get any errors.
	// If any errors where reported, return them.
	for _, r := range rules {
		if r.err != nil {
			return r.err
		}
	}

	// Set the desired rules.
	v.desiredRules = rules
	// v.sortDesiredRules()
	return nil
}

// generateRulesFrom creates rules based on from and from addresses from the r.From slice.
// If From is a hostname DNS resolution will be run on the hostname and all resolved IPs
// will be added as well. If /MASK is missing we will add a /32 mask.
// If there is a validation error or DNS resolution fails an empty rule
// with an error message will be sent to c.
func (v *vpconnect) generateRulesFrom(c chan *parsedRule, w *sync.WaitGroup, r *rule) {
	print(&msg{Message: "v.generateRulesFrom(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRulesFrom(): Returning", LogLevel: "debug"})

	wg := &sync.WaitGroup{}
	defer w.Done()

	currentRule := r

	for _, from := range r.From {
		currentFromList, err := getCIDR(from)
		if err != nil {
			c <- &parsedRule{err: err}
			continue
		}

		// Loop through all resolved addresses.
		for _, fromCIDR := range currentFromList {
			currentFrom := fromCIDR

			wg.Add(1)
			go v.generateRulesTo(c, wg, currentRule, currentFrom)
		}
	}
	wg.Wait()
}

// generateRulesTo creates rules based on from and to addresses from the r.To slice.
// If To is a hostname DNS resolution will be run on the hostname and all resolved IPs
// will be added as well. If /MASK is missing we will add a /32 mask.
// If there is a validation error or DNS resolution fails an empty rule
// with an error message will be sent to c.
func (v *vpconnect) generateRulesTo(c chan *parsedRule, w *sync.WaitGroup, r *rule, from string) {
	print(&msg{Message: "v.generateRulesTo(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRulesTo(): Returning", LogLevel: "debug"})

	wg := &sync.WaitGroup{}
	defer w.Done()

	currentRule := r
	currentFrom := from

	for _, to := range r.To {
		currentToList, err := getCIDR(to)
		if err != nil {
			c <- &parsedRule{err: err}
			continue
		}

		// Loop through all resolved addresses.
		for _, toCIDR := range currentToList {
			currentTo := toCIDR

			wg.Add(1)
			go v.generateRulesProtocol(c, wg, currentRule, currentFrom, currentTo)
		}
	}
	wg.Wait()
}

// generateRulesProtocol creates rules based on from and to and the protocols in the r.Protocols slice.
// If there is a validation error an empty rule with an error message will be sent to c.
// Allowed protocols are tcp, udp and icmp.
func (v *vpconnect) generateRulesProtocol(c chan *parsedRule, w *sync.WaitGroup, r *rule, from string, to string) {
	print(&msg{Message: "v.generateRulesProtocol(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRulesProtocol(): Returning", LogLevel: "debug"})

	wg := &sync.WaitGroup{}
	defer w.Done()

	currentRule := r
	currentFrom := from
	currentTo := to

	for _, protocol := range r.Protocols {
		currentProtocol := strings.ToLower(protocol)
		// Replace -1 with all.
		if currentProtocol == "-1" {
			currentProtocol = "all"
		}

		// Validate that protocol is either tcp, udp or icmp.
		if currentProtocol != "tcp" && currentProtocol != "udp" && currentProtocol != "icmp" && currentProtocol != "all" {
			c <- &parsedRule{err: fmt.Errorf("v.generateRulesProtocol(): Unsupported protocol %s. Supported protocols are tcp, udp, icmp and (all or -1)", currentProtocol)}
			continue
		}

		wg.Add(1)
		go v.generateRulesPort(c, wg, currentRule, currentFrom, currentTo, currentProtocol)
	}
	wg.Wait()
}

// generateRulesPort creates rules based on from, to protocol and masq for
// every entry in r.Ports. If there is a validation error an empty rule
// with an error message will be sent to c.
// Rules for ICMP will be added with port number -1. All other rules
// need to have a port number between 1-65535.
func (v *vpconnect) generateRulesPort(c chan *parsedRule, w *sync.WaitGroup, r *rule, from string, to string, protocol string) {
	print(&msg{Message: "v.generateRulesPort(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRulesPort(): Returning", LogLevel: "debug"})

	wg := &sync.WaitGroup{}
	defer w.Done()

	currentRule := r
	currentFrom := from
	currentTo := to
	currentProtocol := protocol

	switch {
	// Use port value -1 for icmp, to indicate that port is not used.
	case currentProtocol == "icmp":
		currentPort := -1
		wg.Add(1)
		go v.generateRulesFinalize(c, wg, currentRule, currentFrom, currentTo, currentProtocol, currentPort)

	default:
		for _, port := range r.Ports {
			currentPort := port

			// Validate that port is between 1-65535.
			switch {
			case currentPort < 1 && currentPort != -1:
				c <- &parsedRule{err: fmt.Errorf("v.generateRulesPort(): Port was %d. Minimum allowed port value is 1 (or -1 for all ports)", currentPort)}
				continue

			case currentPort > 65535:
				c <- &parsedRule{err: fmt.Errorf("v.generateRulesPort(): Port was %d. Maximum allowed port value is 65535", currentPort)}
				continue
			}

			wg.Add(1)
			go v.generateRulesFinalize(c, wg, currentRule, currentFrom, currentTo, currentProtocol, currentPort)
		}
	}
	wg.Wait()
}

// generateRulesFinalize will put together all the rule and send it to the rule channel
// so it can be merged into a desired rule slice.
func (v *vpconnect) generateRulesFinalize(c chan *parsedRule, w *sync.WaitGroup, r *rule, from string, to string, protocol string, port int) {
	print(&msg{Message: "v.generateRulesFinalize(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.generateRulesFinalize(): Returning", LogLevel: "debug"})

	defer w.Done()

	c <- &parsedRule{
		from:       from,
		to:         to,
		port:       port,
		protocol:   protocol,
		masquerade: r.Masq,
	}
}
