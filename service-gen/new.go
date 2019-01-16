package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func new(name string, env string, region string) error {
	switch {
	case name == "":
		return fmt.Errorf("name must be set when creating a new VPConnect service")

	case env == "":
		return fmt.Errorf("env must be set when creating a new VPConnect service")

	case region == "":
		return fmt.Errorf("region must be set when creating a new VPConnect service")
	}
	dir := fmt.Sprintf("../services/%s-%s", name, env)
	file := fmt.Sprintf("../services/%s-%s/config.yaml", name, env)
	friendlyfile := strings.Replace(file, "../", "", 1)

	// Check if the directory already exists. Then exit with status 1.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return fmt.Errorf("The directory %s already exists", dir)
	}

	// Create the service directory.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("Couldn't create directory %s. Error %s", dir, err.Error())
	}

	// YAML marshal the default configuration.
	bytes, err := yaml.Marshal(newConfig(name, env, region))
	if err != nil {
		return fmt.Errorf("Couldn't YAML Marshal config file. Error %s", err.Error())
	}

	// Save it as a config.yaml.
	if err := ioutil.WriteFile(file, bytes, 0644); err != nil {
		return fmt.Errorf("Couldn't write %s. Error %s", file, err.Error())
	}

	fmt.Printf("VPConnect service for %s-%s created. Please see %s for configuration options\n", name, env, friendlyfile)
	return nil
}

func newConfig(name string, env string, region string) *config {
	instanceType := def["InstanceTypeGlobal"].(string)
	if strings.ToLower(region) == "china" {
		instanceType = def["InstanceTypeChina"].(string)
	}

	return &config{
		Name:        name,
		Environment: env,
		Region:      region,
		Network:     network{},
		Ecs: ecs{
			InstanceType: instanceType,
			Memory:       def["Memory"].(int),
		},
		Vpn: vpn{
			Type:           def["Type"].(string),
			IkeVersion:     def["IkeVersion"].(int),
			CheckInterval:  def["CheckInterval"].(int),
			Encryption:     def["Encryption"].(string),
			Integrity:      def["Integrity"].(string),
			DiffieHellman:  def["DiffieHellman"].(string),
			IkeLifeTime:    def["IkeLifeTime"].(int),
			IpsecLifeTime:  def["IpsecLifeTime"].(int),
			CharonLogLevel: def["CharonLogLevel"].(int),
		},

		Debug: def["Debug"].(bool),

		Rules:   []rule{},
		Ingress: []ingress{},
	}
}
