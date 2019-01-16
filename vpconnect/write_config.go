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

	print(&msg{Message: fmt.Sprintf("v.create(): Creating config for VPN type %s", v.vpnType), LogLevel: "debug"})
	switch {
	case v.vpnType == "virtual":
		return v.configVirtualNet()

	default:
		return v.configSubnetToSubnet()
	}
}

// configSubnetToSubnet will create the config and secrets file for Subnet to Subnet VPN.
// Returns error.
func (v *vpconnect) configSubnetToSubnet() error {
	print(&msg{Message: "v.configSubnetToSubnet(): Entering", LogLevel: "debug"})
	defer print(&msg{Message: "v.configSubnetToSubnet(): Returning", LogLevel: "debug"})

	// Configure /etc/ipsec.conf
	print(&msg{Message: "v.configSubnetToSubnet(): Creating /etc/ipsec.conf", LogLevel: "debug"})
	ipsec := "config setup\n"
	ipsec += "\tuniqueids = yes\n\n"

	// Common base settings
	ipsec += "conn base\n"
	ipsec += "\ttype = tunnel\n"
	ipsec += "\tauthby = secret\n"
	ipsec += "\tforceencaps = yes\n"
	ipsec += "\tdpdaction = none\n"
	ipsec += fmt.Sprintf("\tkeyexchange = ikev%d\n", v.ikeVersion)
	ipsec += fmt.Sprintf("\tike = %s-%s-%s!\n", v.encryption, v.integrity, v.diffieHellman)
	ipsec += fmt.Sprintf("\tesp = %s-%s-%s!\n", v.encryption, v.integrity, v.diffieHellman)
	ipsec += fmt.Sprintf("\tikelifetime = %d\n", v.ikeLifeTime)
	ipsec += fmt.Sprintf("\tlifetime = %d\n\n", v.ipsecLifeTime)

	ipsec += "\t## left\n"
	ipsec += "\tleft = %defaultroute\n"
	ipsec += fmt.Sprintf("\tleftid = %s\n", v.left.elasticIP)
	ipsec += fmt.Sprintf("\tleftsubnet = %s\n", strings.Join(v.left.subnets, ","))
	ipsec += "\tleftauth = psk\n\n"

	ipsec += "\t## right\n"
	ipsec += fmt.Sprintf("\trightsubnet = %s\n", strings.Join(v.right.subnets, ","))
	ipsec += "\trightauth = psk\n\n"

	// Add remote IPs as connections
	for i, ip := range v.right.remoteIPs {
		ipsec += fmt.Sprintf("conn connection%d\n", i)
		ipsec += "\talso = base\n"
		ipsec += "\tauto = start\n"
		ipsec += fmt.Sprintf("\tright = %s\n", ip)
		ipsec += fmt.Sprintf("\trightid = %s\n\n", ip)
	}

	// Write the ipsec.conf file
	print(&msg{Message: "v.configSubnetToSubnet(): Writing /etc/ipsec.conf", LogLevel: "debug"})
	d1 := []byte(ipsec)
	if err := ioutil.WriteFile("/etc/ipsec.conf", d1, 0600); err != nil {
		return fmt.Errorf("v.configSubnetToSubnet(): Couldn't write the /etc/ipsec.conf file. Error %s", err.Error())
	}

	// Configure /etc/ipsec.secrets
	print(&msg{Message: "v.configSubnetToSubnet(): Creating /etc/ipsec.secrets", LogLevel: "debug"})
	psk := ""
	for _, ip := range v.right.remoteIPs {
		psk += fmt.Sprintf("%s %s : PSK \"%s\"\n", v.left.elasticIP, ip, v.psk)
	}
	psk += "\n"

	// Write the ipsec.secrets file
	print(&msg{Message: "v.configSubnetToSubnet(): Writing /etc/ipsec.conf", LogLevel: "debug"})
	d2 := []byte(psk)
	if err := ioutil.WriteFile("/etc/ipsec.secrets", d2, 0600); err != nil {
		return fmt.Errorf("v.configSubnetToSubnet(): Couldn't write the /etc/ipsec.secrets file. Error %s", err.Error())
	}

	// Configure /etc/strongswan.d/charon-logging.conf
	print(&msg{Message: "v.configSubnetToSubnet(): Creating /etc/strongswan.d/charon-logging.conf", LogLevel: "debug"})
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

	// Write the /etc/strongswan.d/charon-logging.conf file
	print(&msg{Message: "v.configSubnetToSubnet(): Writing /etc/strongswan.d/charon-logging.conf", LogLevel: "debug"})
	d3 := []byte(logging)
	if err := ioutil.WriteFile("/etc/strongswan.d/charon-logging.conf", d3, 0600); err != nil {
		return fmt.Errorf("v.configSubnetToSubnet(): Couldn't write the /etc/strongswan.d/charon-logging.conf file. Error %s", err.Error())
	}

	print(&msg{Message: "v.configSubnetToSubnet(): All strongswan config files created", LogLevel: "info"})
	return nil
}

// TODO: Virtual net not yet implemented.
func (*vpconnect) configVirtualNet() error {
	return fmt.Errorf("Virtual network not yet supported")
}
