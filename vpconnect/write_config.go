package main

import (
	"fmt"
	"io/ioutil"
	"strings"
)

// create will create the ipsec config files.
// Returns error.
func (v *vpconnect) create() error {
	print(&msg{Message: "v.create(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.create(): Returning", LogLevel: "debug"})

	print(&msg{Message: "v.create(): Creating config for VPN type", LogLevel: "debug"})
	return v.createIpsecConfig()
}

// writeFile will write data to file.
// Returns error.
func writeFile(data string, fileName string) error {
	print(&msg{Message: "writeFile(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "writeFile(): Returning", LogLevel: "debug"})

	if err := ioutil.WriteFile(fileName, []byte(data), 0600); err != nil {
		return fmt.Errorf("writeFile(): Couldn't write file %s. Error %s", fileName, err.Error())
	}

	print(&msg{Message: fmt.Sprintf("writeFile(): Wrote %s", fileName), LogLevel: "info"})
	return nil
}

// createIpsecConfig will create ipsec.conf, ipsec.secrets config files.
// Returns error.
func (v *vpconnect) createIpsecConfig() error {
	print(&msg{Message: "v.createIpsecConfig(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.createIpsecConfig(): Returning", LogLevel: "debug"})

	// Create the basic config setup for strongswan.
	ipsec, secrets := v.createConnections()
	logging := v.createLogging()

	// Write ipsec.conf, ipsec.secrets and logging.
	if err := writeFile(ipsec, "/etc/ipsec.conf"); err != nil {
		return err
	}
	if err := writeFile(secrets, "/etc/ipsec.secrets"); err != nil {
		return err
	}
	return writeFile(logging, "/etc/strongswan.d/charon-logging.conf")
}

// createConnections creates all the connections stored in v.Connections and returns
// the corresponding connections as ipsec.conf string data and ipsec.secrets string data.
// Returns string (ipsec.conf), string (ipsec.secrets).
func (v *vpconnect) createConnections() (string, string) {
	print(&msg{Message: "v.createConnections(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.createConnections(): Returning", LogLevel: "debug"})

	ipsec := ""
	secrets := ""

	for _, conn := range v.Connections {
		switch conn.Type {
		case "virtual":
			ipsec, secrets = conn.configVirtualNet(v.elasticIp)
		default:
			ipsec, secrets = conn.configSubnetToSubnet(v.elasticIp)
		}
	}

	// Prepend basic ipsec.conf
	ipsec = fmt.Sprintf("config setup\n\tuniqueids = yes\n\n%s", ipsec)

	return ipsec, secrets
}

// createLogging will create the charon logging config data.
// Returns string.
func (v *vpconnect) createLogging() string {
	print(&msg{Message: "v.createLogging(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.createLogging(): Returning", LogLevel: "debug"})

	logging := "charon {\n"
	logging += "\tfilelog {\n"
	logging += "\t\tcharonlog {\n"
	logging += "\t\t\tpath = /var/log/charon.log\n"
	logging += fmt.Sprintf("\t\t\tdefault = %s\n", v.charonLogLevel)
	logging += "\t\t\ttime_format = %Y-%m-%d %H:%M:%S\n"
	logging += "\t\t}\n"
	logging += "\t}\n"
	logging += "\tsyslog {\n"
	logging += "\t\tdaemon {\n"
	logging += "\t\t}\n"
	logging += "\t\tdefault = -1\n"
	logging += "\t}\n"
	logging += "}\n"

	return logging
}

// configSubnetToSubnet will create the data for config and secrets file for Subnet to Subnet VPN.
// You need to supply it with eip (elastic ip).
// Returns error.
func (c *connection) configSubnetToSubnet(eip string) (string, string) {
	print(&msg{Message: "c.configSubnetToSubnet(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "c.configSubnetToSubnet(): Returning", LogLevel: "debug"})

	ipsec := ""
	secrets := ""

	// Create a tunnel for each remote.
	for _, r := range c.Remotes {
		ipsec += fmt.Sprintf("conn %s-%s\n", c.Name, r.Name)
		ipsec += "\ttype = tunnel\n"
		ipsec += "\tauto = start\n"
		ipsec += "\tauthby = secret\n"
		ipsec += "\tforceencaps = yes\n"
		ipsec += "\tdpdaction = none\n"
		ipsec += fmt.Sprintf("\tkeyexchange = ikev%d\n", c.IkeVersion)
		ipsec += fmt.Sprintf("\tike = %s-%s-%s!\n", c.Encryption, c.Integrity, c.DiffieHellman)
		ipsec += fmt.Sprintf("\tesp = %s-%s-%s!\n", c.Encryption, c.Integrity, c.DiffieHellman)
		ipsec += fmt.Sprintf("\tikelifetime = %d\n", c.IkeLifeTime)
		ipsec += fmt.Sprintf("\tlifetime = %d\n\n", c.IpsecLifeTime)

		ipsec += "\t## left\n"
		ipsec += "\tleft = %defaultroute\n"
		ipsec += fmt.Sprintf("\tleftid = %s\n", eip)
		ipsec += fmt.Sprintf("\tleftsubnet = %s\n", strings.Join(c.Local.Subnets, ","))
		ipsec += "\tleftauth = psk\n\n"

		ipsec += "\t## right\n"
		ipsec += fmt.Sprintf("\tright = %s\n", r.Ip)
		ipsec += fmt.Sprintf("\trightid = %s\n\n", r.Id)
		ipsec += fmt.Sprintf("\trightsubnet = %s\n", strings.Join(r.Subnets, ","))
		ipsec += "\trightauth = psk\n\n"

		secrets += fmt.Sprintf("%s %s : PSK \"%s\"\n", eip, r.Ip, c.Psk)
	}

	return ipsec, secrets
}

// TODO: Virtual net not yet implemented.
func (*connection) configVirtualNet(eip string) (string, string) {
	return "", ""
}
