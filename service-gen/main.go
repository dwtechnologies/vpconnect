package main

import (
	"fmt"
	"os"
)

type file struct {
	FriendlyName string `yaml:"FriendlyName"`
	Name         string `yaml:"Name"`

	Network network `yaml:"Network"`
	Ecs     ecs     `yaml:"Ecs"`

	Config config `yaml:"Config"`

	Debug bool `yaml:"Debug"`

	Ingress []ingress `yaml:"Ingress"`

	// Below are only used internally for templating.
	AutoIngressString   string `yaml:"-"`
	ManualIngressString string `yaml:"-"`
	ConfigString        string `yaml:"-"`
	KmsString           string `yaml:"-"`
}

// vpconnect contains the data that will be base64 encoded
// and set as an env variable in the docker image.
type config struct {
	Connections   []connection `yaml:"Connections"`
	Rules         []rule       `yaml:"Rules"`
	CheckInterval int          `yaml:"CheckInterval"`
	NoIpsec       bool         `yaml:"NoIpsec"`
}

type network struct {
	VpcId           string `yaml:"VpcId"`
	PrivateSubnetId string `yaml:"PrivateSubnetId"`
	PublicSubnetId  string `yaml:"PublicSubnetId"`
}

type ecs struct {
	InstanceType string `yaml:"InstanceType"`
	Memory       int    `yaml:"Memory"`
	DockerImage  string `yaml:"DockerImage"`
	SshKeyName   string `yaml:"SshKeyName"`
	KmsKeyArn    string `yaml:"KmsKeyArn"`
	AlarmSnsArn  string `yaml:"AlarmSnsArn"`
}

type connection struct {
	Name          string `yaml:"Name"`
	Type          string `yaml:"Type"`
	IkeVersion    int    `yaml:"IkeVersion"`
	PskEncrypted  string `yaml:"PskEncrypted"`
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

type rule struct {
	From        []string    `yaml:"From"`
	To          []string    `yaml:"To"`
	Ports       []int       `yaml:"Ports"`
	PortForward map[int]int `yaml:"PortForward"`
	Protocols   []string    `yaml:"Protocols"`
	Masq        bool        `yaml:"Masq"`
}

type ingress struct {
	CidrIp                     string `yaml:"CidrIp,omitempty"`
	CidrIpv6                   string `yaml:"CidrIpv6,omitempty"`
	Description                string `yaml:"Description,omitempty"`
	FromPort                   int    `yaml:"FromPort,omitempty"`
	ToPort                     int    `yaml:"ToPort,omitempty"`
	GroupId                    string `yaml:"GroupId,omitempty"`
	GroupName                  string `yaml:"GroupName,omitempty"`
	IpProtocol                 string `yaml:"IpProtocol,omitempty"`
	SourceSecurityGroupName    string `yaml:"SourceSecurityGroupName,omitempty"`
	SourceSecurityGroupId      string `yaml:"SourceSecurityGroupId,omitempty"`
	SourceSecurityGroupOwnerId string `yaml:"SourceSecurityGroupOwnerId,omitempty"`
}

type policy struct {
	PolicyName     string           `yaml:"PolicyName"`
	PolicyDocument []policyDocument `yaml:"PolicyDocument"`
}

type policyDocument struct {
	Effect   string   `yaml:"Effect"`
	Action   []string `yaml:"Action"`
	Resource string   `yaml:"Resource"`
}

// - PolicyName: "kms-decrypt"
// PolicyDocument:
//   Statement:
// 	- Effect: "Allow"
// 	  Action:
// 		- "kms:Decrypt"
// 	  Resource: "{{.Ecs.KmsKeyArn}}"

func main() {
	args := os.Args

	switch {
	case args[1] == "new" && len(args) == 3:
		if err := new(args[2]); err != nil {
			exit(err)
		}

	case args[1] == "gen" && len(args) == 3:
		if err := gen(args[2]); err != nil {
			exit(err)
		}

	default:
		printUsageAndExit(args[0])
	}
}

// exit will just print the error message and the exit 1.
func exit(err error) {
	fmt.Printf("%s\n", err.Error())
	os.Exit(1)
}

// printUsageAndExit will print the usage and exit with exit code 1.
// name is the executable name and should be retrieved in the calling
// function with os.Args[0].
func printUsageAndExit(name string) {
	fmt.Printf("Usage: %s <CMD> <NAME>\n", name)
	fmt.Printf("Where <CMD> can be either:\n")
	fmt.Printf("  new  For creating a new vpconnect vpn service and creating config.yaml\n")
	fmt.Printf("  gen  For generating the cf template from config.yaml\n\n")
	os.Exit(1)
}
