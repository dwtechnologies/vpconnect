package main

var (
	def = map[string]interface{}{
		"InstanceTypeGlobal": "t3.nano",
		"InstanceTypeChina":  "t2.nano",
		"Memory":             384,
		"Type":               "subnet",
		"IkeVersion":         2,
		"CheckInterval":      300,
		"Debug":              false,
		"CharonLogLevel":     1,
		"Encryption":         "aes256",
		"Integrity":          "sha256",
		"DiffieHellman":      "modp2048",
		"IkeLifeTime":        10800,
		"IpsecLifeTime":      3600,
	}
)
