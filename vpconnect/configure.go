package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/dwtechnologies/kmsdecrypt"
)

// config will fetch and configure vpconnect by retrieving config from
// env variables. It will also do some sanity checks on key config elements.
// As well as set sensible defaults on others if not set.
// Returns error.
func config() (*vpconnect, error) {
	print(&msg{Message: "v.config(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.config(): Returning", LogLevel: "debug"})

	// Unmarshal the config.
	v, err := configUnmarshal()
	if err != nil {
		return nil, err
	}
	// Create the stopping channel.
	v.configStoppingChan()
	// Validate and set Elastic IP
	if err := v.configElasticIp(); err != nil {
		return nil, err
	}

	// Don't configure IPSec if we shouldn't run it.
	if !v.NoIpsec {
		// Validate Connections.
		if err := v.configConnections(); err != nil {
			return nil, err
		}
		// Set Charon debug level.
		v.configCharonLogLevel()
	}

	print(&msg{Message: "v.config(): Getting configuration done", LogLevel: "info"})
	return v, nil
}

// removeSpaces will remove any spaces from str.
// Returns string.
func removeSpaces(str string) string {
	return strings.Replace(str, " ", "", -1)
}

// stringExists checks if val exists in slice or not.
// If it exists returns true.
// Returns bool
func stringExists(val string, slice []string) bool {
	for _, sliceVal := range slice {
		if sliceVal == val {
			return true
		}
	}
	return false
}

// intExists checks if val exists in slice or not.
// If it exists returns true.
// Returns bool
func intExists(val int, slice []int) bool {
	for _, sliceVal := range slice {
		if sliceVal == val {
			return true
		}
	}
	return false
}

// configUnmarshal will get the CONFIG env var and base64 decode it and
// YAML Unmarshal it to a vpconnect struct and return it and error.
// Returns *vpconnect and error.
func configUnmarshal() (*vpconnect, error) {
	print(&msg{Message: "configUnmarshal(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "configUnmarshal(): Returning", LogLevel: "debug"})

	base := removeSpaces(os.Getenv("CONFIG"))

	// Check that config isn't just an empty string.
	if base == "" {
		return nil, fmt.Errorf("configUnmarshal(): CONFIG not set")
	}

	// base64 decode the CONFIG env var.
	raw, err := base64.StdEncoding.DecodeString(base)
	if err != nil {
		return nil, fmt.Errorf("configUnmarshal(): Couldn't base64 decode CONFIG. Error %s", err.Error())
	}

	// Unmarshal the CONFIG env var.
	v := &vpconnect{}
	if err := yaml.Unmarshal(raw, v); err != nil {
		return nil, fmt.Errorf("configUnmarshal(): Couldn't unmarshal CONFIG to YAML. Error %s", err.Error())
	}

	print(&msg{Message: "configUnmarshal(): Successfully unmarshaled CONFIG", LogLevel: "info"})
	return v, nil
}

// configStoppingChan creates the stopping channel.
func (v *vpconnect) configStoppingChan() {
	print(&msg{Message: "v.configStoppingChan(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configStoppingChan(): Returning", LogLevel: "debug"})

	v.stopping = make(chan bool)
}

// configElasticIp will get the Elastic Ip from env variable and set it to vpconnect.
// Returns error.
func (v *vpconnect) configElasticIp() error {
	print(&msg{Message: "v.configElasticIp(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configElasticIp(): Returning", LogLevel: "debug"})

	eip := removeSpaces(os.Getenv("ELASTIC_IP"))

	// Check that eip is not empty.
	if eip == "" {
		return fmt.Errorf("v.configElasticIp(): ELASTIC_IP not set")
	}

	// Validate IP the Elastic IP.
	if !isValidIP(eip) {
		return fmt.Errorf("v.configElasticIp(): Invalid IP found for Elastic IP. Got %s", eip)
	}

	v.elasticIp = eip
	print(&msg{Message: fmt.Sprintf("v.configElasticIp(): Elastic IP set to %s", eip), LogLevel: "info"})
	return nil
}

// configConnections will loop over all connections and configure and
// validate them.
// Returns error.
func (v *vpconnect) configConnections() error {
	for _, conn := range v.Connections {
		// Validate Connection name.
		conNames := []string{}
		if err := conn.configName(conNames); err != nil {
			return err
		}
		// Valdidate Connection VPN type.
		if err := conn.configVpnType(); err != nil {
			return err
		}
		// Validate IKE Version.
		if err := conn.configIkeVersion(); err != nil {
			return err
		}
		// Config PSK.
		if err := conn.configPSK(); err != nil {
			return err
		}
		// Config Encryption.
		if err := conn.configEncryption(); err != nil {
			return err
		}
		// Config Integrity.
		if err := conn.configIntegrity(); err != nil {
			return err
		}
		// Config DiffieHellman.
		if err := conn.configDiffieHellman(); err != nil {
			return err
		}
		// Config IKE Lifetime.
		conn.configIkeLifeTime()
		// Config IPSec Lifetime.
		conn.configIpsecLifeTime()
		// Config Local.
		if err := conn.configLocal(); err != nil {
			return err
		}
		// Config Remotes.
		if err := conn.configRemotes(); err != nil {
			return err
		}
	}
	return nil
}

// configName checks that Name is set on the connection. Returns error if it's not set.
// Checks that the name is unique and doesn't exists in names.
// Returns error
func (c *connection) configName(names []string) error {
	print(&msg{Message: "c.configName(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configName(): Returning", LogLevel: "debug"})

	// If Name is empty return error.
	if c.Name == "" {
		return fmt.Errorf("c.configName(): Name not set in one or more connections")
	}

	// Check if name is unique.
	if stringExists(c.Name, names) {
		return fmt.Errorf("c.configName(): Connection Name must be unique")
	}

	names = append(names, c.Name)
	return nil
}

// configVpnType validates the connections vpn type.
// Returns error.
func (c *connection) configVpnType() error {
	print(&msg{Message: "c.configVpnType(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configVpnType(): Returning", LogLevel: "debug"})

	// If c.Type is empty, default to subnet.
	if c.Type == "" {
		c.Type = "subnet"
	}

	// Check if the specified type exists in the allowedVpnTypes slice.
	if !stringExists(c.Type, allowedVpnTypes) {
		return fmt.Errorf("c.configVpnType(): Connection %s's VPN type %s is not a valid. Valid values %s", c.Name, c.Type, allowedVpnTypes)
	}

	print(&msg{Message: fmt.Sprintf("c.configVpnType(): Connection %s configured as VPN type %s", c.Name, c.Type), LogLevel: "info"})
	return nil
}

// configIkeVersion validates the connections IKE version.
// Returns error.
func (c *connection) configIkeVersion() error {
	print(&msg{Message: "c.configIkeVersion(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configIkeVersion(): Returning", LogLevel: "debug"})

	// If IkeVersion is 0, default to 2.
	if c.IkeVersion == 0 {
		c.IkeVersion = 2
	}

	// Check if the specified IkeVersion exists in allowedIkeversions slice.
	if !intExists(c.IkeVersion, allowedIkeVersions) {
		return fmt.Errorf("c.configIkeVersion(): Connection %s's IKE version %d isn't valid. Valid values %d", c.Name, c.IkeVersion, allowedIkeVersions)
	}

	print(&msg{Message: fmt.Sprintf("c.configIkeVersion(): Connection %s configured as IKE version %d", c.Name, c.IkeVersion), LogLevel: "info"})
	return nil
}

// configPSK will decrypt the PSK set by env variable. Check that it's between 32 and 64 characters
// in length (otherwise it's seen as insecure). And set the decrypted PSK to vpconnect.
// Returns error.
func (c *connection) configPSK() error {
	print(&msg{Message: "c.configPSK(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configPSK(): Returning", LogLevel: "debug"})

	// Get the encrypted PSK.
	print(&msg{Message: "c.configPSK(): Checking encrypted PSK", LogLevel: "debug"})
	if c.PskEncrypted == "" {
		return fmt.Errorf("c.configPSK(): PskEncrypted not set")
	}

	// Get the KMS region.
	print(&msg{Message: "c.configPSK(): Getting KMS region", LogLevel: "debug"})
	region := removeSpaces(os.Getenv("KMS_REGION"))
	if region == "" {
		return fmt.Errorf("c.configPSK(): KMS_REGION not set")
	}

	// Create the KSM decrypter.
	print(&msg{Message: "c.configPSK(): Creating KMS decrypter", LogLevel: "debug"})
	d, err := kmsdecrypt.New(region)
	if err != nil {
		return fmt.Errorf("c.configPSK(): Couldn't create decrypter. Error %s", err.Error())
	}

	// Decrypt the PSK.
	print(&msg{Message: "c.configPSK(): Decrypting PSK", LogLevel: "debug"})
	psk, err := d.DecryptString(c.PskEncrypted)
	if err != nil {
		return fmt.Errorf("c.configPSK(): Couldn't decrypt PSK. Error %s", err.Error())
	}

	// Check PSK length.
	if len(psk) < 32 || len(psk) > 64 {
		return fmt.Errorf("c.configPSK(): Decrypted PSK must be betwen 32 and 64 characters")
	}
	c.psk = psk
	c.PskEncrypted = ""

	print(&msg{Message: "c.configPSK(): PSK decrypted and set", LogLevel: "info"})
	return nil
}

// configEncryption validates and sets the encryption algo.
// Returns error.
func (c *connection) configEncryption() error {
	print(&msg{Message: "c.configEncryption(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configEncryption(): Returning", LogLevel: "debug"})

	// Default to aes256 if encryption not set.
	if c.Encryption == "" {
		c.Encryption = "aes256"
	}

	// Check if the specified type exists in the allowedEncryption slice.
	if !stringExists(c.Encryption, allowedEncryption) {
		return fmt.Errorf("c.configEncryption(): Encryption %s is not a valid. Valid values are %s", c.Encryption, allowedEncryption)
	}

	return nil
}

// configIntegrity validates and sets the integrity algo.
// Returns error.
func (c *connection) configIntegrity() error {
	print(&msg{Message: "c.configIntegrity(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configIntegrity(): Returning", LogLevel: "debug"})

	// Integrity is not set, default to sha256.
	if c.Integrity == "" {
		c.Integrity = "sha256"
	}

	// Check if the specified type exists in the allowedIntegrity slice.
	if !stringExists(c.Integrity, allowedIntegrity) {
		return fmt.Errorf("c.configIntegrity(): Integrity %s is not a valid. Valid values are %s", c.Integrity, allowedIntegrity)
	}

	return nil
}

// configDiffieHellman validates and sets the diffiehellman group.
// Returns error.
func (c *connection) configDiffieHellman() error {
	print(&msg{Message: "c.configDiffieHellman(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configDiffieHellman(): Returning", LogLevel: "debug"})

	// Default to modp2048 if DiffieHellman is not set.
	if c.DiffieHellman == "" {
		c.DiffieHellman = "modp2048"
	}

	// Check if the specified type exists in the allowedDiffieHellman slice.
	if !stringExists(c.DiffieHellman, allowedDiffieHellman) {
		return fmt.Errorf("c.configDiffieHellman(): DiffieHellman %s is not a valid. Valid values are %s", c.DiffieHellman, allowedDiffieHellman)
	}

	return nil
}

// configLocal validates the connections Local configuration.
// Returns error.
func (c *connection) configLocal() error {
	print(&msg{Message: "c.configLocal(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configLocal(): Returning", LogLevel: "debug"})

	// Check that Local Subnets is not empty.
	if len(c.Local.Subnets) == 0 {
		return fmt.Errorf("c.configLocal: Connection %s doesn't contain any local subnets", c.Name)
	}

	// Loop over all local subnets. If any of the subnets are invalid
	// return error.
	for _, subnet := range c.Local.Subnets {
		if !isValidCIDR(subnet) {
			return fmt.Errorf("c.configLocal: Connection %s has an invalid local subnet %s", c.Name, subnet)
		}
	}
	return nil
}

// configIkeLifeTime validates and sets the IKE Life Time.
func (c *connection) configIkeLifeTime() {
	print(&msg{Message: "c.configIkeLifeTime(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configIkeLifeTime(): Returning", LogLevel: "debug"})

	// Set default IKE lifetime if 0.
	if c.IkeLifeTime == 0 {
		c.IkeLifeTime = 10800
	}
}

// configIpsecLifeTime validates and sets the Ipsec Life Time.
func (c *connection) configIpsecLifeTime() {
	print(&msg{Message: "c.configIpsecLifeTime(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configIpsecLifeTime(): Returning", LogLevel: "debug"})

	// Set default IPSec lifetime if 0.
	if c.IpsecLifeTime == 0 {
		c.IpsecLifeTime = 3600
	}
}

// configRemotes validates a connections remotes.
// Returns error.
func (c *connection) configRemotes() error {
	print(&msg{Message: "c.configRemotes(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configRemotes(): Returning", LogLevel: "debug"})

	// Check that remotes is not empty.
	if len(c.Remotes) == 0 {
		return fmt.Errorf("c.configLocal: Connection %s doesn't contain any remotes", c.Name)
	}

	// Loop over all remotes and validate them. If anyone contains an error
	// return error.
	for _, remote := range c.Remotes {
		// Validate remote name.
		remoteNames := []string{}
		if err := remote.configRemoteName(remoteNames); err != nil {
			return err
		}
		// Validate remote IP.
		if err := remote.configRemoteIp(); err != nil {
			return err
		}
		// Validate remote ID.
		remote.configRemoteId()
		// Validate remote subnets.
		if err := remote.configRemoteSubnets(); err != nil {
			return err
		}
	}
	return nil
}

// configRemoteName validates a remotes name.
func (r *remote) configRemoteName(names []string) error {
	print(&msg{Message: "r.configRemoteName(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "r.configRemoteName(): Returning", LogLevel: "debug"})

	// Check that r.Name isn't empty.
	if r.Name == "" {
		return fmt.Errorf("r.configRemoteName(): Name not set in one or more remotes")
	}

	// Check if name is unique.
	if stringExists(r.Name, names) {
		return fmt.Errorf("r.configRemoteName(): Connection Name must be unique")
	}

	names = append(names, r.Name)
	return nil
}

// configRemoteIp will validate a remotes IP.
// Returns error.
func (r *remote) configRemoteIp() error {
	print(&msg{Message: "r.configRemoteIp(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "r.configRemoteIp(): Returning", LogLevel: "debug"})

	// Validate that IP is a valid IP.
	if !isValidIP(r.Ip) {
		return fmt.Errorf("r.configRemoteIp(): Remote %s contains an invalid IP %s", r.Name, r.Ip)
	}
	return nil
}

// configRemoteId will validate a remotes ID.
func (r *remote) configRemoteId() {
	print(&msg{Message: "r.configRemoteId(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "r.configRemoteId(): Returning", LogLevel: "debug"})

	// Validate that ID is set, otherwise set IP as the value of ID.
	if r.Id == "" {
		r.Id = r.Id
	}
}

// configRemoteSubnets validates a remotes subnets.
// Returns error.
func (r *remote) configRemoteSubnets() error {
	print(&msg{Message: "r.configRemoteSubnets(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "r.configRemoteSubnets(): Returning", LogLevel: "debug"})

	// Check that Remote Subnets is not empty.
	if len(r.Subnets) == 0 {
		return fmt.Errorf("c.configRemoteSubnets: Remote %s doesn't contain any subnets", r.Name)
	}

	// Loop over all remote subnets. If any of the subnets are invalid
	// return error.
	for _, subnet := range r.Subnets {
		if !isValidCIDR(subnet) {
			return fmt.Errorf("c.configRemoteSubnets: Remote %s has an invalid local subnet %s", r.Name, subnet)
		}
	}
	return nil
}

// configCharonLogLevel will get set to 3 if debug is active.
// Otherwise it will be set to 1.
func (v *vpconnect) configCharonLogLevel() {
	print(&msg{Message: "v.configCharonLogLevel(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configCharonLogLevel(): Returning", LogLevel: "debug"})

	// Set charon log level based on debug.
	switch debug {
	case true:
		v.charonLogLevel = 3

	default:
		v.charonLogLevel = 1
	}

	print(&msg{Message: fmt.Sprintf("v.configCharonLogLevel(): Charon Log Level set to %d", v.charonLogLevel), LogLevel: "info"})
}
