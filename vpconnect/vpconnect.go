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
	elasticIp string

	Connections []*connection `yaml:"Connections"`
	Rules       []*rule       `yaml:"Rules"`

	CheckInterval int `yaml:"CheckInterval"`

	// Don't start charon. Program can be used as PF.
	NoIpsec bool `yaml:"NoIpsec"`

	desiredRules []*parsedRule
	activeRules  []*parsedRule

	charonLogLevel int
	check          *time.Ticker
	stopping       chan bool
}

type connection struct {
	Name          string `yaml:"Name"`
	Type          string `yaml:"Type"`
	IkeVersion    int    `yaml:"IkeVersion`
	PskEncrypted  string `yaml:"PskEncrypted"`
	Psk           string `yaml:"Psk"`
	Encryption    string `yaml:"Encryption"`
	Integrity     string `yaml:"Integrity"`
	DiffieHellman string `yaml:"DiffieHellman"`
	IkeLifeTime   int    `yaml:"IkeLifeTime"`
	IpsecLifeTime int    `yaml:"IpsecLifeTime"`

	Local   local    `yaml:"Local"`
	Remotes []remote `yaml:"Remotes"`
}

type local struct {
	Subnets []string `yaml:"Subnets"`
}

type remote struct {
	Name    string   `yaml:"Name"`
	Ip      string   `yaml:"Ip"`
	Id      string   `yaml:"Id"`
	Subnets []string `yaml:"Subnets"`
}

// rule contains the raw rule before it's been processed to a format
// that can be used by iptables.
type rule struct {
	From        []string     `yaml:"From"`
	To          []string     `yaml:"To"`
	Ports       []int        `yaml:"Ports"`
	Protocols   []string     `yaml:"Protocols"`
	Masq        bool         `yaml:"Masq"`
	PortForward *portForward `yaml:"PortForward"`
}

// portForward enables port forward instead of VPN based rules.
// It will allow traffic to the EIP and forward it and do port
// translation if enabled.
type portForward struct {
	Enabled bool        `yaml:"Enabled"`
	PortMap map[int]int `yaml:"PortMap"`
}

// parsedRule contains the rule in a way that can be used by iptables.
type parsedRule struct {
	to         string
	from       string
	port       int
	protocol   string
	masquerade bool
	err        error
}

// Allowed types. Currently we only support subnet-2-subnet VPN (subnet).
var allowedVpnTypes = []string{"subnet", "virtual"}

var allowedIkeVersions = []int{1, 2}

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

	// Config and return a vpconnect and error.
	return config()
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
