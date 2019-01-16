package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/dwtechnologies/kmsdecrypt"
)

// config will fetch and configure vpconnect by retrieving config from
// env variables. It will also do some sanity checks on key config elements.
// As well as set sensible defaults on others if not set.
// Returns error.
func (v *vpconnect) config() error {
	print(&msg{Message: "v.config(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.config(): Returning", LogLevel: "debug"})

	// Validate and set VPN Type
	if err := v.configVpnType(); err != nil {
		return err
	}
	// Validate and set VPN Ike Version
	if err := v.configIkeVersion(); err != nil {
		return err
	}
	// Validate and set Elastic IP
	if err := v.configElasticIP(); err != nil {
		return err
	}
	// Validate and set Remote IPs
	if err := v.configRemoteIPs(); err != nil {
		return err
	}
	// Validate and set left and right subnets
	if err := v.configSubnets(); err != nil {
		return err
	}
	// Validate and set PSK
	if err := v.configPSK(); err != nil {
		return err
	}
	// Validate ands et charon log level.
	if err := v.configCharonLogLevel(); err != nil {
		return err
	}
	// Get Imported Rules.
	if err := v.configImportedRules(); err != nil {
		return err
	}
	// Configure Encryption.
	if err := v.configEncryption(); err != nil {
		return err
	}
	// Configure Integrity.
	if err := v.configIntegrity(); err != nil {
		return err
	}
	// Configure Diffie Hellman.
	if err := v.configDiffieHellman(); err != nil {
		return err
	}
	// Configure IKE Life Time.
	if err := v.configIkeLifeTime(); err != nil {
		return err
	}
	// Configure IPSEC Life Time.
	if err := v.configIpsecLifeTime(); err != nil {
		return err
	}

	print(&msg{Message: "v.config(): Getting configuration done", LogLevel: "info"})
	return nil
}

// configVpnType validates and sets the vpn type.
// Returns error.
func (v *vpconnect) configVpnType() error {
	print(&msg{Message: "v.configVpnType(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configVpnType(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	vpnType := strings.Replace(os.Getenv("VPN_TYPE"), " ", "", -1)

	if vpnType == "" {
		vpnType = "subnet"
	}

	// Check if the specified type exists in the allowedVpnTypes slice.
	for _, t := range allowedVpnTypes {
		if t == vpnType {
			v.vpnType = vpnType
			return nil
		}
	}

	return fmt.Errorf("v.configVpnType(): VPN_TYPE %s is not a valid. Valid values are %s", vpnType, allowedVpnTypes)
}

// configIkeVersion validates and sets the ike version.
// Returns error.
func (v *vpconnect) configIkeVersion() error {
	print(&msg{Message: "v.configIkeVersion(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configIkeVersion(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	ikeString := strings.Replace(os.Getenv("IKE_VERSION"), " ", "", -1)
	ike, err := strconv.Atoi(ikeString)
	if err != nil {
		return fmt.Errorf("v.configIkeVersion(): IKE_VERSION couldn't be converted to integer. Valid values are between 1 or 2. Current value %s", ikeString)
	}

	if ike != 1 && ike != 2 {
		return fmt.Errorf("v.configIkeVersion(): IKE_VERSION isn't valid. Valid values are between 1 or 2. Current value %d", ike)
	}

	v.ikeVersion = ike
	return nil
}

// configElasticIP will get the Elastic IP from env variable and set it to vpconnect.
// Returns error.
func (v *vpconnect) configElasticIP() error {
	print(&msg{Message: "v.configElasticIP(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configElasticIP(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	eip := strings.Replace(os.Getenv("ELASTIC_IP"), " ", "", -1)

	switch {
	case eip == "":
		return fmt.Errorf("v.configElasticIP(): ELASTIC_IP not set")

	default:
		v.left.elasticIP = eip
	}

	print(&msg{Message: fmt.Sprintf("v.configElasticIP(): Elastic IP set to %s", eip), LogLevel: "info"})
	return nil
}

// configRemoteIPs will configure the Primary and Secondary Remote IPs and set them to vpconnect.
// Returns error.
func (v *vpconnect) configRemoteIPs() error {
	print(&msg{Message: "v.configRemoteIPs(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configRemoteIPs(): Returning", LogLevel: "debug"})

	str := strings.Replace(os.Getenv("REMOTE_IPS"), " ", "", -1)
	if str == "" {
		return fmt.Errorf("v.configRemoteIPs(): REMOTE_IPS not set")
	}

	// Slice REMOTE_IPS variable
	ips := strings.Split(str, ",")

	for _, ip := range ips {
		if v.isValidIP(ip) {
			v.right.remoteIPs = append(v.right.remoteIPs, ip)
			print(&msg{Message: fmt.Sprintf("v.configRemoteIPs(): Remote IP %s added", ip), LogLevel: "info"})
		}
	}

	if len(v.right.remoteIPs) == 0 {
		return fmt.Errorf("v.configRemoteIPs(): No valid Remote IPs found")
	}

	return nil
}

// configSubnets configures the left and right subnets and sets them to vpconnect.
// Returns error.
func (v *vpconnect) configSubnets() error {
	print(&msg{Message: "v.configSubnets(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configSubnets(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	ls := strings.Split(strings.Replace(os.Getenv("SUBNETS_LOCAL"), " ", "", -1), ",")
	rs := strings.Split(strings.Replace(os.Getenv("SUBNETS_REMOTE"), " ", "", -1), ",")

	switch {
	case len(ls) == 0:
		return fmt.Errorf("v.configSubnets(): SUBNETS_LOCAL not set")

	case len(rs) == 0:
		return fmt.Errorf("v.configSubnets(): SUBNETS_REMOTE not set")

	default:
		v.left.subnets = ls
		v.right.subnets = rs
	}

	print(&msg{Message: fmt.Sprintf("v.configSubnets(): Local subnets %s, Remote subnets %s", ls, rs), LogLevel: "info"})
	return nil
}

// configPSK will decrypt the PSK set by env variable. Check that it's between 32 and 64 characters
// in length (otherwise it's seen as insecure). And set the decrypted PSK to vpconnect.
// Returns error.
func (v *vpconnect) configPSK() error {
	print(&msg{Message: "v.configPSK(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configPSK(): Returning", LogLevel: "debug"})

	// If unencrypted PSK is set, use that instead of encrypted on.
	// This is basically a work around to get it working in cn regions
	// where there is no KMS.
	print(&msg{Message: "v.configPSK(): Getting unencrypted PSK", LogLevel: "debug"})
	unencryptedPsk := strings.Replace(os.Getenv("PSK"), " ", "", -1)
	if len(unencryptedPsk) > 32 && len(unencryptedPsk) < 64 {
		v.psk = unencryptedPsk

		print(&msg{Message: "v.configPSK(): PSK set", LogLevel: "info"})
		return nil
	}

	// Get the encrypted PSK.
	print(&msg{Message: "v.configPSK(): Getting encrypted PSK", LogLevel: "debug"})
	encryptedPsk := strings.Replace(os.Getenv("PSK_ENCRYPTED"), " ", "", -1)
	if encryptedPsk == "" {
		return fmt.Errorf("v.configPSK(): PSK_ENCRYPTED not set")
	}

	// Get the KMS region.
	print(&msg{Message: "v.configPSK(): Getting KMS region", LogLevel: "debug"})
	region := strings.Replace(os.Getenv("KMS_REGION"), " ", "", -1)
	if region == "" {
		return fmt.Errorf("v.configPSK(): KMS_REGION not set")
	}

	// Create the KSM decrypter.
	print(&msg{Message: "v.configPSK(): Creating KMS decrypter", LogLevel: "debug"})
	d, err := kmsdecrypt.New(region)
	if err != nil {
		return fmt.Errorf("v.configPSK(): Couldn't create decrypter. Error %s", err.Error())
	}

	// Decrypt the PSK.
	print(&msg{Message: "v.configPSK(): Decrypting PSK", LogLevel: "debug"})
	psk, err := d.DecryptString(encryptedPsk)
	if err != nil {
		return fmt.Errorf("v.configPSK(): Couldn't decrypt PSK. Error %s", err.Error())
	}

	// Check PSK length.
	if len(psk) < 32 || len(psk) > 64 {
		return fmt.Errorf("v.configPSK(): Decrypted PSK must be betwen 32 and 64 characters")
	}
	v.psk = psk

	print(&msg{Message: "v.configPSK(): PSK decrypted and set", LogLevel: "info"})
	return nil
}

// configCharonLogLevel will get the log level for charon from
// env var and set it to vpconnect. The value must be an integer
// between 1 and 3 to be valid. It will not accept logging off (0)
// or to high logging (above 3), since that will log PSK passwords
// and other sensitive data.
// Returns error.
func (v *vpconnect) configCharonLogLevel() error {
	print(&msg{Message: "v.configCharonLogLevel(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configCharonLogLevel(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	c := strings.Replace(os.Getenv("CHARON_LOG_LEVEL"), " ", "", -1)

	switch {
	case c == "":
		v.charonLogLevel = "1"

	default:
		charon, err := strconv.Atoi(c)
		if err != nil {
			return fmt.Errorf("v.configCharonLogLevel(): CHARON_LOG_LEVEL set but couldn't be converted to integer. Valid values are between 1, 2 or 3. Current value %s", c)
		}

		// Check that charon logging is between 1-3.
		// Thats so that we at least have logging but not
		// so much logging that we send PSK secrets.
		if charon < 1 || charon > 3 {
			return fmt.Errorf("v.configCharonLogLevel(): CHARON_LOG_LEVEL set but is invalid. Valid values are between 1, 2 or 3. Current value %d", charon)
		}

		v.charonLogLevel = c
	}

	print(&msg{Message: fmt.Sprintf("v.configCharonLogLevel(): Charon Log Level set to %s", v.charonLogLevel), LogLevel: "info"})
	return nil
}

// configImportedRules will get the RULES env var and base64 decode it and
// YAML Unmarshal it to a slice of importedRules and set it to the v.importedRules.
// These are then used for generating the desired rules/active rules.
// Returns error.
func (v *vpconnect) configImportedRules() error {
	print(&msg{Message: "v.configImportedRules(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configImportedRules(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	base := strings.Replace(os.Getenv("RULES"), " ", "", -1)
	if base == "" {
		return fmt.Errorf("v.configImportedRules(): RULES not set")
	}

	// base64 decode the RULES vars.
	raw, err := base64.StdEncoding.DecodeString(base)
	if err != nil {
		return fmt.Errorf("v.configImportedRules(): Couldn't base64 decode RULES. Error %s", err.Error())
	}

	// Unmarshal the rules.
	rules := []importedRule{}
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		return fmt.Errorf("v.configImportedRules(): Couldn't unmarshal RULES yaml to []importedRules. Error %s", err.Error())
	}

	// Set the imported rules.
	v.importedRules = rules

	print(&msg{Message: "v.configImportedRules(): Successfully decoded Rules", LogLevel: "info"})
	return nil
}

// configEncryption validates and sets the encryption algo.
// Returns error.
func (v *vpconnect) configEncryption() error {
	print(&msg{Message: "v.configEncryption(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configEncryption(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	enc := strings.Replace(os.Getenv("ENCRYPTION"), " ", "", -1)

	if enc == "" {
		enc = "aes256"
	}

	// Check if the specified type exists in the allowedEncryption slice.
	for _, e := range allowedEncryption {
		if e == enc {
			v.encryption = enc
			return nil
		}
	}

	return fmt.Errorf("v.configEncryption(): ENCRYPTION %s is not a valid. Valid values are %s", enc, allowedEncryption)
}

// configIntegrity validates and sets the integrity algo.
// Returns error.
func (v *vpconnect) configIntegrity() error {
	print(&msg{Message: "v.configIntegrity(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configIntegrity(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	integrity := strings.Replace(os.Getenv("INTEGRITY"), " ", "", -1)

	if integrity == "" {
		integrity = "sha256"
	}

	// Check if the specified type exists in the allowedEncryption slice.
	for _, i := range allowedIntegrity {
		if i == integrity {
			v.integrity = integrity
			return nil
		}
	}

	return fmt.Errorf("v.configIntegrity(): INTEGRITY %s is not a valid. Valid values are %s", integrity, allowedIntegrity)
}

// configDiffieHellman validates and sets the diffiehellman group.
// Returns error.
func (v *vpconnect) configDiffieHellman() error {
	print(&msg{Message: "v.configDiffieHellman(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configDiffieHellman(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	dh := strings.Replace(os.Getenv("DIFFIE_HELLMAN"), " ", "", -1)

	if dh == "" {
		dh = "modp2048"
	}

	// Check if the specified type exists in the allowedEncryption slice.
	for _, d := range allowedDiffieHellman {
		if d == dh {
			v.diffieHellman = dh
			return nil
		}
	}

	return fmt.Errorf("v.configDiffieHellman(): DIFFIE_HELLMAN %s is not a valid. Valid values are %s", dh, allowedDiffieHellman)
}

// configIkeLifeTime validates and sets the IKE Life Time.
// Returns error.
func (v *vpconnect) configIkeLifeTime() error {
	print(&msg{Message: "v.configIkeLifeTime(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configIkeLifeTime(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	ike, err := strconv.Atoi(strings.Replace(os.Getenv("IKE_LIFETIME"), " ", "", -1))
	if err != nil {
		return fmt.Errorf("v.configIkeLifeTime(): IKE_LIFETIME %s couldn't be converted to integer", os.Getenv("IKE_LIFETIME"))
	}

	if ike == 0 {
		ike = 10800
	}

	v.ikeLifeTime = ike
	return nil
}

// configIpsecLifeTime validates and sets the Ipsec Life Time.
// Returns error.
func (v *vpconnect) configIpsecLifeTime() error {
	print(&msg{Message: "v.configIpsecLifeTime(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configIpsecLifeTime(): Returning", LogLevel: "debug"})

	// Replace any accidental spaces.
	ipsec, err := strconv.Atoi(strings.Replace(os.Getenv("IPSEC_LIFETIME"), " ", "", -1))
	if err != nil {
		return fmt.Errorf("v.configIpsecLifeTime(): IPSEC_LIFETIME %s couldn't be converted to integer", os.Getenv("IPSEC_LIFETIME"))
	}

	if ipsec == 0 {
		ipsec = 3600
	}

	v.ipsecLifeTime = ipsec
	return nil
}
