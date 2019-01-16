package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

func gen(name string, env string) error {
	cfgFile := fmt.Sprintf("../services/%s-%s/config.yaml", name, env)
	cfTemplate := fmt.Sprintf("../services/%s-%s/cf.yaml", name, env)
	cfTemplateFriendly := strings.Replace(cfTemplate, "../", "", 1)

	// Read the config.yaml file for the specified service.
	b, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		return fmt.Errorf("Couldn't read file %s. Error %s", cfgFile, err.Error())
	}

	// Unmarshal the config file to the config struct.
	c := &config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return fmt.Errorf("Couldn't unmarshal %s. Error %s", cfgFile, err.Error())
	}

	if err := c.validateConfig(); err != nil {
		return err
	}

	// Parse template.
	templ := "../cf-template.yaml"
	if strings.ToLower(c.Region) == "china" {
		templ = "../cf-template-cn.yaml"
	}

	t, err := template.ParseFiles(templ)
	if err != nil {
		return fmt.Errorf("Couldn't open template file. Error %s", err.Error())
	}

	// Add automatic and manual security group settings.
	// And set Rules to a base64 representation of the yaml value.
	// Also generate a string-representation of the SA subnets.
	if err = c.generateAutomaticIngress(); err != nil {
		return err
	}
	if err = c.generateManualIngress(); err != nil {
		return err
	}
	if err = c.generateRules(); err != nil {
		return err
	}
	c.generateRemoteIps()
	c.generateSubnets()

	// Create the cf-template.yaml file.
	f, err := os.Create(cfTemplate)
	if err != nil {
		return fmt.Errorf("Couldn't create %s. Error %s", cfTemplate, err.Error())
	}

	// Run replacement on template.
	if err := t.Execute(f, c); err != nil {
		return fmt.Errorf("Error generating template. Error %s", err.Error())
	}

	fmt.Printf("CloudFormation file %s generated!\n", cfTemplateFriendly)
	return nil
}

// generateAutomaticIngress will generate the necessary YAML security group settings
// for accepting isakmp and esp from the Primary and (if set) Secondary Remote IPs.
// It will then marshal it to a bytes representation of the YAML array.
// Returns error.
func (c *config) generateAutomaticIngress() error {
	a := []ingress{}

	// Add the Remote IPs to the slice.
	for _, ip := range c.Vpn.RemoteIps {
		a = append(a,
			ingress{
				Description: "Allow ipsec/isakmp",
				IpProtocol:  "udp",
				FromPort:    500,
				ToPort:      500,
				CidrIp:      fmt.Sprintf("%s/32", ip),
			},
			ingress{
				Description: "Allow ipsec/esp",
				IpProtocol:  "udp",
				FromPort:    4500,
				ToPort:      4500,
				CidrIp:      fmt.Sprintf("%s/32", ip),
			},
		)
	}

	// Marshal to to YAML
	b, err := yaml.Marshal(a)
	if err != nil {
		return fmt.Errorf("Couldn't marshal the automatic ingress rules. Error %s", err.Error())
	}

	c.AutoIngressString = strings.Replace(string(b), "\n", "\n        ", -1)
	return nil
}

// generateManualIngress will generate the necessary YAML security group settings
// for any manual added security group ingress rules. It wil set the c.ManualIngressString
// with the marshaled byte representation of the YAML array.
// Returns error.
func (c *config) generateManualIngress() error {
	// Ingress slice has length 0, just return so that we will run replacement with an empty string.
	// Thus not generating any manual rules at all.
	if len(c.Ingress) == 0 {
		return nil
	}

	b, err := yaml.Marshal(c.Ingress)
	if err != nil {
		return fmt.Errorf("Couldn't marshal manual ingress rules. Error %s", err.Error())
	}

	c.ManualIngressString = strings.Replace(fmt.Sprintf("# Manual Ingress rules\n%s", string(b)), "\n", "\n        ", -1)
	return nil
}

// generateRules will generate the necessary rules and base64 encode the yaml representation
// and set it to c.Rules.
// Returns error
func (c *config) generateRules() error {
	b, err := yaml.Marshal(c.Rules)
	if err != nil {
		return fmt.Errorf("Couldn't marshal rules. Error %s", err.Error())
	}

	c.RulesString = base64.StdEncoding.EncodeToString(b)
	return nil
}

// generateRemoteIps will convert the slice of strings to a string representation of the slice.
func (c *config) generateRemoteIps() {
	c.RemoteIpsString = strings.Join(c.Vpn.RemoteIps, ",")
}

// generateSubnets will convert the slice of strings to a string representation of the slice.
func (c *config) generateSubnets() {
	c.LocalSubnetsString = strings.Join(c.Vpn.LocalSubnets, ",")
	c.RemoteSubnetsString = strings.Join(c.Vpn.RemoteSubnets, ",")
}

// validateConfig runs some simple validation on c to make sure that at least the most
// basic stuff is there and seems ok.
// Returns error.
func (c *config) validateConfig() error {
	switch {
	case c.FriendlyName == "":
		return fmt.Errorf("FriendlyName is required and can't be empty")
	case c.Name == "":
		return fmt.Errorf("Name is required and can't be empty")
	case c.Environment == "":
		return fmt.Errorf("Environment is required and can't be empty")
	case len(c.Rules) == 0:
		return fmt.Errorf("You need at least 1 Rule")
	case c.Network.VpcId == "":
		return fmt.Errorf("Network.VpcID is required and can't be empty")
	case c.Network.PublicSubnetId == "":
		return fmt.Errorf("Network.PublicSubnetId is required and can't be empty")
	case c.Network.PrivateSubnetId == "":
		return fmt.Errorf("Network.PrivateSubnetId is required and can't be empty")
	case c.Ecs.InstanceType == "":
		return fmt.Errorf("Ecs.InstanceType is required and can't be empty")
	case c.Ecs.Memory == 0:
		return fmt.Errorf("Ecs.Memory is required and can't be empty/0")
	case c.Ecs.DockerImage == "":
		return fmt.Errorf("Ecs.DockerImage is required and can't be empty")
	case c.Ecs.SshKeyName == "":
		return fmt.Errorf("Ecs.SshKeyName is required and can't be empty")
	case c.Ecs.KmsKeyArn == "" && strings.ToLower(c.Region) != "china":
		return fmt.Errorf("Ecs.KmsKeyArn is required and can't be empty")
	case c.Ecs.AlarmSnsArn == "":
		return fmt.Errorf("Ecs.AlarmSnsArn is required and can't be empty")
	case c.Ecs.AmiImageId == "" && strings.ToLower(c.Region) == "china":
		return fmt.Errorf("Ecs.AmiImageId is required and can't be empty")
	case c.Vpn.Type == "":
		return fmt.Errorf("Vpn.Type is required and can't be empty")
	case c.Vpn.IkeLifeTime == 0:
		return fmt.Errorf("Vpn.IkeVersion is required and must be either 1 or 2")
	case c.Vpn.PskEncrypted == "" && strings.ToLower(c.Region) != "china":
		return fmt.Errorf("Vpn.PskEncrypted is required and can't be empty")
	case c.Vpn.Psk == "" && strings.ToLower(c.Region) == "china":
		return fmt.Errorf("Vpn.Psk is required and can't be empty")
	case len(c.Vpn.LocalSubnets) == 0:
		return fmt.Errorf("You need at least 1 Vpn.LocalSubnets")
	case len(c.Vpn.RemoteSubnets) == 0:
		return fmt.Errorf("You need at least 1 Vpn.RemoteSubnets")
	case strings.Join(c.Vpn.RemoteIps, ",") == "":
		return fmt.Errorf("Vpn.RemotePrimaryIP is required and can't be empty")
	case c.Vpn.Encryption == "":
		return fmt.Errorf("Vpn.Encryption is required and can't be empty")
	case c.Vpn.Integrity == "":
		return fmt.Errorf("Vpn.Integrity is required and can't be empty")
	case c.Vpn.DiffieHellman == "":
		return fmt.Errorf("Vpn.DiffieHellman is required and can't be empty")
	case c.Vpn.IkeLifeTime == 0:
		return fmt.Errorf("Vpn.IkeLifeTime is required and can't be empty/0")
	case c.Vpn.IpsecLifeTime == 0:
		return fmt.Errorf("Vpn.IpsecLifeTime is required and can't be empty/0")
	case c.Vpn.CharonLogLevel == 0:
		return fmt.Errorf("Vpn.CharonLogLevel is required and can't be empty/0")
	}

	// All is good.
	return nil
}
