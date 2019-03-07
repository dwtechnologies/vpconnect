package main

var (
	def = map[string]interface{}{
		"InstanceType":  "t2.nano",
		"Memory":        384,
		"Type":          "subnet",
		"IkeVersion":    2,
		"CheckInterval": 300,
		"Debug":         false,
		"Encryption":    "aes256",
		"Integrity":     "sha256",
		"DiffieHellman": "modp2048",
		"IkeLifeTime":   10800,
		"IpsecLifeTime": 3600,
	}
)
