package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

func new(name string) error {
	if name == "" {
		return fmt.Errorf("name must be set when creating a new VPConnect service")
	}
	dir := fmt.Sprintf("../services/%s", name)
	file := fmt.Sprintf("../services/%s/config.yaml", name)
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
	bytes, err := yaml.Marshal(newConfig(name))
	if err != nil {
		return fmt.Errorf("Couldn't YAML Marshal config file. Error %s", err.Error())
	}

	// Save it as a config.yaml.
	if err := ioutil.WriteFile(file, bytes, 0644); err != nil {
		return fmt.Errorf("Couldn't write %s. Error %s", file, err.Error())
	}

	fmt.Printf("VPConnect service for %s created. Please see %s for configuration options\n", name, friendlyfile)
	return nil
}

func newConfig(name string) *file {
	return &file{
		Name:    name,
		Network: network{},
		Ecs: ecs{
			InstanceType: def["InstanceType"].(string),
			Memory:       def["Memory"].(int),
		},

		Config: config{
			Connections: []connection{
				connection{
					Type:          def["Type"].(string),
					IkeVersion:    def["IkeVersion"].(int),
					Encryption:    def["Encryption"].(string),
					Integrity:     def["Integrity"].(string),
					DiffieHellman: def["DiffieHellman"].(string),
					IkeLifeTime:   def["IkeLifeTime"].(int),
					IpsecLifeTime: def["IpsecLifeTime"].(int),
				},
			},
			Rules:         []rule{},
			CheckInterval: def["CheckInterval"].(int),
			NoIpsec:       def["NoIpsec"].(bool),
		},

		Debug: def["Debug"].(bool),

		Ingress: []ingress{},
	}
}
