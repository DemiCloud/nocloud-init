package types

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v2"
)

type UserData struct {
	Hostname       string `yaml:"hostname" json:"hostname"`
	ManageEtcHosts bool   `yaml:"manage_etc_hosts" json:"manage_etc_hosts"`
	FQDN           string `yaml:"fqdn" json:"fqdn"`
	User           string `yaml:"user" json:"user"`
	Password       string `yaml:"password" json:"password"`
	// Chpasswd is defined by the NoCloud spec but Expire is not yet implemented.
	Chpasswd struct {
		Expire bool `yaml:"expire" json:"expire"`
	} `yaml:"chpasswd" json:"chpasswd"`
	// Users is defined by the NoCloud spec but not yet implemented.
	// Proxmox does not populate this field; support may be added in a future release.
	Users []string `yaml:"users" json:"users"`
}

// NetworkConfig supports both NoCloud network-config v1 and v2 formats.
// Only one of Config (v1) or Ethernets (v2) will be populated depending on Version.
type NetworkConfig struct {
	Version   int                               `yaml:"version" json:"version"`
	Config    []NetworkConfigV1Entry            `yaml:"config" json:"config"`              // v1
	Ethernets map[string]NetworkConfigV2Ethernet `yaml:"ethernets" json:"ethernets"` // v2
}

// NetworkConfigV1Entry is a single entry in a v1 network-config.
// Type is one of "physical" or "nameserver".
type NetworkConfigV1Entry struct {
	Type       string                 `yaml:"type" json:"type"`
	Name       string                 `yaml:"name" json:"name"`
	MacAddress string                 `yaml:"mac_address" json:"mac_address"`
	Subnets    []NetworkConfigV1Subnet `yaml:"subnets" json:"subnets"`
	Address    []string               `yaml:"address" json:"address"`
	Search     []string               `yaml:"search" json:"search"`
}

type NetworkConfigV1Subnet struct {
	Type    string `yaml:"type" json:"type"`
	Address string `yaml:"address" json:"address"`
	Netmask string `yaml:"netmask" json:"netmask"`
	Gateway string `yaml:"gateway" json:"gateway"`
}

// NetworkConfigV2Ethernet is an entry in a v2 network-config ethernets map.
// Addresses use CIDR notation (e.g. "192.168.1.10/24").
// Set DHCP4 to true for DHCP configuration.
type NetworkConfigV2Ethernet struct {
	Match struct {
		MACAddress string `yaml:"macaddress" json:"macaddress"`
	} `yaml:"match" json:"match"`
	SetName     string   `yaml:"set-name" json:"set-name"`
	Addresses   []string `yaml:"addresses" json:"addresses"`
	Gateway4    string   `yaml:"gateway4" json:"gateway4"`
	DHCP4       bool     `yaml:"dhcp4" json:"dhcp4"`
	Nameservers struct {
		Addresses []string `yaml:"addresses" json:"addresses"`
		Search    []string `yaml:"search" json:"search"`
	} `yaml:"nameservers" json:"nameservers"`
}

func UnmarshalUserData(data []byte, ud *UserData) error {
	yamlErr := yaml.Unmarshal(data, ud)
	if yamlErr == nil {
		return nil
	}
	if err := json.Unmarshal(data, ud); err == nil {
		return nil
	}
	return fmt.Errorf("yaml: %v", yamlErr)
}

func UnmarshalNetworkConfig(data []byte, nc *NetworkConfig) error {
	yamlErr := yaml.Unmarshal(data, nc)
	if yamlErr == nil {
		return nil
	}
	if err := json.Unmarshal(data, nc); err == nil {
		return nil
	}
	return fmt.Errorf("yaml: %v", yamlErr)
}
