package main

import (
	"fmt"
	"os"
	"time"
)

// vpconnect is the main struct of the vpconnect program.
// It contains config needed to both generate the ipsec config files as well
// as updating iptables with the correct rules.
type vpconnect struct {
	vpnType       string
	ikeVersion    int
	psk           string
	encryption    string
	integrity     string
	diffieHellman string
	ikeLifeTime   int
	ipsecLifeTime int

	left  left
	right right

	importedRules []importedRule
	desiredRules  []*rule
	activeRules   []*rule

	charonLogLevel string
	check          *time.Ticker
	stopping       chan bool
}

type left struct {
	elasticIP string
	subnets   []string
}

type right struct {
	remoteIPs []string
	subnets   []string
}

// importedRule is based to unmarshal and handle the base64 encoded rules
// gathered from the ENV var RULES. These rules will be parsed and transformed
// into vpconnect.rules.
type importedRule struct {
	From      []string `yaml:"From"`
	To        []string `yaml:"To"`
	Ports     []int    `yaml:"Ports"`
	Protocols []string `yaml:"Protocols"`
	Masq      bool     `yaml:"Masq"`
}

// rule contains the pure rule that can be used to create an iptables rule.
type rule struct {
	to         string
	from       string
	port       int
	protocol   string
	masquerade bool
	err        error
}

// Allowed types. Currently we only support subnet-2-subnet VPN (subnet).
var allowedVpnTypes = []string{"subnet", "virtual"}

// Allowed encryption.
var allowedEncryption = []string{"aes", "aes128", "aes192", "aes256", "aes128ctr", "aes192ctr", "aes256ctr", "aes128ccm8", "aes128ccm64", "aes192ccm8", "aes192ccm64",
	"aes256ccm8", "aes256ccm64", "aes128ccm12", "aes128ccm96", "aes192ccm12", "aes192ccm96", "aes256ccm12", "aes256ccm96", "aes128ccm16", "aes128ccm128", "aes192ccm16",
	"aes192ccm128", "aes256ccm16", "aes256ccm128", "aes128gcm8", "aes128gcm64", "aes192gcm8", "aes192gcm64", "aes256gcm8", "aes256gcm64", "aes128gcm12", "aes128gcm96",
	"aes192gcm12", "aes192gcm96", "aes256gcm12", "aes256gcm96", "aes128gcm16", "aes128gcm128", "aes192gcm16", "aes192gcm128"}

// Allowed integrity.
var allowedIntegrity = []string{"aesxcbc", "aescmac", "sha1", "sha", "sha256", "sha2_256", "sha384", "sha2_384", "sha512", "sha2_512"}

// Allowed DiffieHellman groups.
var allowedDiffieHellman = []string{"modp1536", "modp2048", "modp3072", "modp4096", "modp6144", "modp8192", "ecp384", "ecp521", "ecp192", "ecp224", "ecp224bp", "ecp256bp", "ecp384bp", "ecp512bp"}

// new initiates a new vpconnect.
// Returns error.
func new() (*vpconnect, error) {
	print(&msg{Message: "new(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "new(): Returning", LogLevel: "debug"})

	// Init vpconnect.
	print(&msg{Message: "new(): Init vpconnect", LogLevel: "debug"})

	v := &vpconnect{
		stopping: make(chan bool),
	}

	// Configure vpconnect.
	if err := v.config(); err != nil {
		return nil, err
	}

	return v, nil
}

// wait will wait until we get a message on the v.stopping channel.
// The wait function will exit(1) if any errors occur while stopping,
// otherwise we exit with exit(0).
func (v *vpconnect) wait() {
	print(&msg{Message: "v.wait(): Entering", LogLevel: "debug"})

	<-v.stopping
	v.check.Stop()

	if err := v.stop(); err != nil {
		print(&msg{Message: err.Error(), LogLevel: "error"})
		exit(1)
	}

	exit(0)
}

// exit will print an exit notice that is pushed to CloudWatch logs and exit with exit code code.
// If exit code is 0 (successfull exit) set loglevel info. Otherwise log it with loglevel error.
func exit(code int) {
	switch code {
	case 0:
		print(&msg{Message: fmt.Sprintf("exit(): Exiting program with exit code %d", code), LogLevel: "info"})
	default:
		print(&msg{Message: fmt.Sprintf("exit(): Exiting program with exit code %d", code), LogLevel: "error"})
	}

	os.Exit(code)
}
