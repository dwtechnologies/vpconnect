package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// start will start ipsec charon server by running "ipsec start". It will wait until the
// command has finished and will return any error.
func (v *vpconnect) start() error {
	print(&msg{Message: "v.start(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.start(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.start(): Running ipsec start", LogLevel: "debug"})
	if err := exec.Command("ipsec", "start").Run(); err != nil {
		return err
	}

	print(&msg{Message: "v.start(): ipsec started", LogLevel: "info"})
	return nil
}

// restart will restart ipsec charon server by running "ipsec restart". It will wait until the
// command has finished and will return any error.
func (v *vpconnect) restart() error {
	print(&msg{Message: "v.restart(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.restart(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.restart(): Running ipsec restart", LogLevel: "debug"})
	if err := exec.Command("ipsec", "restart").Run(); err != nil {
		return err
	}

	print(&msg{Message: "v.restart(): ipsec restarted", LogLevel: "info"})
	return nil
}

// status will return the value of ipsec [status|statusall]. if all is set to true
// it will return the value of ipsec statusall instead of just status.
// Returns string and error
func (v *vpconnect) status(all bool) (string, error) {
	print(&msg{Message: "v.status(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.status(): Returning", LogLevel: "debug"})

	// If we should get status by running status or statusall.
	arg := "status"
	if all {
		arg = "statusall"
	}

	print(&msg{Message: fmt.Sprintf("v.status(): Running ipsec %s", arg), LogLevel: "debug"})
	o, err := exec.Command("ipsec", arg).Output()
	if err != nil {
		return "", err
	}

	print(&msg{Message: fmt.Sprintf("v.status(): %s", string(o)), LogLevel: "debug"})
	return string(o), nil
}

// stop will stop ipsec charon server by running "ipsec stop". It will wait until the
// command has finished and will return any error.
func (v *vpconnect) stop() error {
	print(&msg{Message: "v.stop(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.stop(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.stop(): Running ipsec stop", LogLevel: "debug"})
	if err := exec.Command("ipsec", "stop").Run(); err != nil {
		return err
	}

	print(&msg{Message: "v.stop(): ipsec stopped", LogLevel: "info"})
	return nil
}

// ipsec will start a go-routine that checks that IPSec is running.
func (v *vpconnect) ipsec() {
	print(&msg{Message: "v.ipsec(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.ipsec(): Returning", LogLevel: "debug"})
	ticker := time.NewTicker(time.Duration(60 * time.Second)) // Set the timer to 60.

	go func() {
		for {
			print(&msg{Message: "v.ipsec(): Checking IPSec status", LogLevel: "debug"})

			res, err := v.status(false)
			if err != nil {
				print(&msg{Message: err.Error(), LogLevel: "error"})
				v.stopping <- true
				return
			}

			// Depending on various IPSec status states.
			switch {
			// IPSec isn't running.
			case res == "":
				print(&msg{Message: "v.ipsec(): IPSec not running. Attempting to start it", LogLevel: "warning"})
				if err := v.start(); err != nil {
					print(&msg{Message: err.Error(), LogLevel: "error"})
					v.stopping <- true
					return
				}

			// IPSec is running, but 0 up or connecting.
			case strings.Contains(res, "(0 up, 0 connecting)"):
				print(&msg{Message: "v.ipsec(): IPSec is running. But tunnel isn't up or trying to connect. Restarting", LogLevel: "warning"})
				if err := v.restart(); err != nil {
					print(&msg{Message: err.Error(), LogLevel: "error"})
					v.stopping <- true
					return
				}
			}

			// Wait for 60 seconds.
			<-ticker.C
		}
	}()
}
