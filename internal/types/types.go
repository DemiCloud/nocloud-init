package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuncmdItem represents a single entry in the runcmd cloud-config list.
// Per the cloud-init spec, each entry is either:
//   - a plain string, which is passed to "sh -c <string>"
//   - a list of strings, which is executed directly via execve (no shell)
//
// Only one of Shell or Args will be set after unmarshaling.
type RuncmdItem struct {
	Shell string   // non-empty: run via sh -c
	Args  []string // non-nil: exec directly
}

func (r *RuncmdItem) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		r.Shell = value.Value
		return nil
	case yaml.SequenceNode:
		var args []string
		if err := value.Decode(&args); err != nil {
			return fmt.Errorf("runcmd item sequence: %w", err)
		}
		r.Args = args
		return nil
	default:
		return fmt.Errorf("runcmd item must be a string or a list of strings")
	}
}

func (r *RuncmdItem) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		r.Shell = s
		return nil
	}
	var args []string
	if err := json.Unmarshal(data, &args); err != nil {
		return fmt.Errorf("runcmd item must be a string or list of strings: %w", err)
	}
	r.Args = args
	return nil
}

// GroupEntry describes a single group to create, with an optional list of
// existing users to add as members.
type GroupEntry struct {
	Name    string
	Members []string
}

// GroupList is the parsed form of the cloud-config groups key.
// The key accepts:
//   - a comma-separated string:  "sudo, docker"
//   - a sequence where each item is either a plain group name or a mapping
//     of {groupname: member} or {groupname: [member1, member2]}
type GroupList []GroupEntry

func (g *GroupList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		for _, name := range strings.Split(value.Value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				*g = append(*g, GroupEntry{Name: name})
			}
		}
		return nil
	case yaml.SequenceNode:
		for _, item := range value.Content {
			switch item.Kind {
			case yaml.ScalarNode:
				*g = append(*g, GroupEntry{Name: item.Value})
			case yaml.MappingNode:
				if len(item.Content) != 2 {
					return fmt.Errorf("groups mapping entry must have exactly one key")
				}
				name := item.Content[0].Value
				valNode := item.Content[1]
				var members []string
				switch valNode.Kind {
				case yaml.ScalarNode:
					if valNode.Value != "" {
						members = []string{valNode.Value}
					}
				case yaml.SequenceNode:
					if err := valNode.Decode(&members); err != nil {
						return fmt.Errorf("groups %q members: %w", name, err)
					}
				default:
					return fmt.Errorf("groups %q members must be a string or list", name)
				}
				*g = append(*g, GroupEntry{Name: name, Members: members})
			default:
				return fmt.Errorf("groups list item must be a string or mapping")
			}
		}
		return nil
	default:
		return fmt.Errorf("groups must be a string or list")
	}
}

func (g *GroupList) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		for _, name := range strings.Split(s, ",") {
			if name = strings.TrimSpace(name); name != "" {
				*g = append(*g, GroupEntry{Name: name})
			}
		}
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("groups must be a string or array: %w", err)
	}
	for _, item := range raw {
		var name string
		if err := json.Unmarshal(item, &name); err == nil {
			*g = append(*g, GroupEntry{Name: name})
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(item, &m); err != nil {
			return fmt.Errorf("groups item must be a string or object: %w", err)
		}
		for gname, membersRaw := range m {
			entry := GroupEntry{Name: gname}
			var ms string
			var ml []string
			if err := json.Unmarshal(membersRaw, &ms); err == nil {
				if ms != "" {
					entry.Members = []string{ms}
				}
			} else if err := json.Unmarshal(membersRaw, &ml); err == nil {
				entry.Members = ml
			}
			*g = append(*g, entry)
		}
	}
	return nil
}

// UserGroupList parses either a comma-separated string or a sequence of
// strings from a users.[].groups field.
type UserGroupList []string

func (u *UserGroupList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		for _, g := range strings.Split(value.Value, ",") {
			if g = strings.TrimSpace(g); g != "" {
				*u = append(*u, g)
			}
		}
		return nil
	case yaml.SequenceNode:
		var groups []string
		if err := value.Decode(&groups); err != nil {
			return fmt.Errorf("users groups: %w", err)
		}
		*u = groups
		return nil
	default:
		return fmt.Errorf("users.groups must be a string or list")
	}
}

func (u *UserGroupList) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		for _, g := range strings.Split(s, ",") {
			if g = strings.TrimSpace(g); g != "" {
				*u = append(*u, g)
			}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("users.groups must be a string or list: %w", err)
	}
	*u = list
	return nil
}

// UserEntry describes a single user to create from the users cloud-config list.
// The special name "default" is recognized and skipped.
type UserEntry struct {
	Name              string        `yaml:"name" json:"name"`
	Gecos             string        `yaml:"gecos" json:"gecos"`
	Groups            UserGroupList `yaml:"groups" json:"groups"`
	Shell             string        `yaml:"shell" json:"shell"`
	// HashedPasswd is a pre-hashed crypt(3) string (e.g. "$6$...").
	HashedPasswd      string        `yaml:"hashed_passwd" json:"hashed_passwd"`
	// LockPasswd locks the account after creation when true.
	LockPasswd        bool          `yaml:"lock_passwd" json:"lock_passwd"`
	// NoCreateHome skips home directory creation.
	NoCreateHome      bool          `yaml:"no_create_home" json:"no_create_home"`
	// System creates the user as a system account.
	System            bool          `yaml:"system" json:"system"`
	// Sudo is the rule written to /etc/sudoers.d/<name>. Empty means no rule.
	Sudo              string        `yaml:"sudo" json:"sudo"`
	// SSHAuthorizedKeys are public keys installed for this user.
	SSHAuthorizedKeys []string      `yaml:"ssh_authorized_keys" json:"ssh_authorized_keys"`
}

// UserList is the parsed form of the users cloud-config key.
// Each item is either the string "default" (skipped) or a user mapping.
type UserList []UserEntry

func (u *UserList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("users must be a sequence")
	}
	for _, item := range value.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			*u = append(*u, UserEntry{Name: item.Value})
		case yaml.MappingNode:
			var entry UserEntry
			if err := item.Decode(&entry); err != nil {
				return fmt.Errorf("users entry: %w", err)
			}
			*u = append(*u, entry)
		default:
			return fmt.Errorf("users item must be a string or mapping")
		}
	}
	return nil
}

func (u *UserList) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("users must be an array: %w", err)
	}
	for _, item := range raw {
		var s string
		if err := json.Unmarshal(item, &s); err == nil {
			*u = append(*u, UserEntry{Name: s})
			continue
		}
		var entry UserEntry
		if err := json.Unmarshal(item, &entry); err != nil {
			return fmt.Errorf("users entry: %w", err)
		}
		*u = append(*u, entry)
	}
	return nil
}

// WriteFile describes a single file entry from the write_files cloud-config
// directive.  Content is decoded according to Encoding before writing:
//   - "" or "text/plain" — written as-is
//   - "b64" / "base64" — base64-decoded first (whitespace is stripped)
//   - "gz" / "gzip" — gzip-decompressed (useful for binary blobs in JSON payloads)
//   - "gz+b64" / "gz+base64" / "gzip+b64" / "gzip+base64" — base64-decoded then gzip-decompressed
//
// Permissions is an octal string (e.g. "0644"); defaults to "0644".
// Owner is "user:group" or "user"; defaults to root (no chown called).
// If Append is true, content is appended to an existing file rather than
// replacing it.
type WriteFile struct {
	Path        string `yaml:"path" json:"path"`
	Content     string `yaml:"content" json:"content"`
	Encoding    string `yaml:"encoding" json:"encoding"`
	Owner       string `yaml:"owner" json:"owner"`
	Permissions string `yaml:"permissions" json:"permissions"`
	Append      bool   `yaml:"append" json:"append"`
}

type UserData struct {
	Hostname       string `yaml:"hostname" json:"hostname"`
	ManageEtcHosts bool   `yaml:"manage_etc_hosts" json:"manage_etc_hosts"`
	FQDN           string `yaml:"fqdn" json:"fqdn"`
	User           string `yaml:"user" json:"user"`
	// Password must be a pre-hashed credential (e.g. "$6$..."). Plaintext
	// passwords are not supported; the value is passed verbatim to chpasswd -e.
	Password string `yaml:"password" json:"password"`
	// Chpasswd is defined by the NoCloud spec but Expire is not yet implemented.
	Chpasswd struct {
		Expire bool `yaml:"expire" json:"expire"`
	} `yaml:"chpasswd" json:"chpasswd"`
	// Users lists users to create. The special entry "default" is skipped.
	Users UserList `yaml:"users" json:"users"`
	// SSHAuthorizedKeys lists public keys to install for User.
	// Each run replaces the nocloud-init–managed block in the user's
	// authorized_keys file, leaving any pre-existing keys untouched.
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys" json:"ssh_authorized_keys"`
	// WriteFiles lists files to create or update on the system.
	WriteFiles []WriteFile `yaml:"write_files" json:"write_files"`
	// Runcmd lists commands to run after all other configuration is applied.
	// Each item is either a shell string (run via sh -c) or a list of exec args.
	Runcmd []RuncmdItem `yaml:"runcmd" json:"runcmd"`
	// Groups lists groups to create on the system, with optional members.
	Groups GroupList `yaml:"groups" json:"groups"`
}

// NetworkConfig supports both NoCloud network-config v1 and v2 formats.
// Only one of Config (v1) or Ethernets (v2) will be populated depending on Version.
type NetworkConfig struct {
	Version   int                               `yaml:"version" json:"version"`
	Config    []NetworkConfigV1Entry            `yaml:"config" json:"config"`              // v1
	Ethernets map[string]NetworkConfigV2Ethernet `yaml:"ethernets" json:"ethernets"` // v2
	VLANs     map[string]NetworkConfigV2VLAN    `yaml:"vlans" json:"vlans"`         // v2
	Bonds     map[string]NetworkConfigV2Bond    `yaml:"bonds" json:"bonds"`         // v2
}

// NetworkConfigV2VLAN describes a VLAN interface in a v2 network-config.
// ID is the 802.1Q VLAN tag (0–4094). Link is the ID of the parent ethernet
// entry. All common per-device properties (addresses, dhcp4, dhcp6, etc.) are
// inherited from NetworkConfigV2Ethernet via embedding.
type NetworkConfigV2VLAN struct {
	ID   int    `yaml:"id" json:"id"`
	Link string `yaml:"link" json:"link"`
	NetworkConfigV2Ethernet `yaml:",inline" json:",inline"`
}

// NetworkConfigV2BondParameters holds optional bonding mode parameters.
// Fields map directly to the [Bond] section of a systemd-networkd .netdev file.
type NetworkConfigV2BondParameters struct {
	Mode               string `yaml:"mode" json:"mode"`
	LACPRate           string `yaml:"lacp-rate" json:"lacp-rate"`
	MIIMonitorInterval string `yaml:"mii-monitor-interval" json:"mii-monitor-interval"`
	MinLinks           int    `yaml:"min-links" json:"min-links"`
	TransmitHashPolicy string `yaml:"transmit-hash-policy" json:"transmit-hash-policy"`
	ARPInterval        string `yaml:"arp-interval" json:"arp-interval"`
	UpDelay            string `yaml:"up-delay" json:"up-delay"`
	DownDelay          string `yaml:"down-delay" json:"down-delay"`
}

// NetworkConfigV2Bond describes a bond interface in a v2 network-config.
// Interfaces lists the IDs of the ethernet entries that form the bond members.
// Parameters contains optional bonding mode configuration.
// All common per-device properties (addresses, dhcp4, dhcp6, etc.) are
// inherited from NetworkConfigV2Ethernet via embedding.
type NetworkConfigV2Bond struct {
	Interfaces []string                       `yaml:"interfaces" json:"interfaces"`
	Parameters NetworkConfigV2BondParameters  `yaml:"parameters" json:"parameters"`
	NetworkConfigV2Ethernet `yaml:",inline" json:",inline"`
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
	Type             string   `yaml:"type" json:"type"`
	Address          string   `yaml:"address" json:"address"`
	Netmask          string   `yaml:"netmask" json:"netmask"`
	Gateway          string   `yaml:"gateway" json:"gateway"`
	DNSNameservers   []string `yaml:"dns_nameservers" json:"dns_nameservers"`
	DNSSearch        []string `yaml:"dns_search" json:"dns_search"`
}

// NetworkConfigV2Ethernet is an entry in a v2 network-config ethernets map.
// Addresses use CIDR notation (e.g. "192.168.1.10/24").
// Set DHCP4 to true for DHCPv4, DHCP6 for DHCPv6, or both for dual-stack DHCP.
type NetworkConfigV2Ethernet struct {
	Match struct {
		MACAddress string `yaml:"macaddress" json:"macaddress"`
	} `yaml:"match" json:"match"`
	SetName     string   `yaml:"set-name" json:"set-name"`
	Addresses   []string `yaml:"addresses" json:"addresses"`
	Gateway4    string   `yaml:"gateway4" json:"gateway4"`
	Gateway6    string   `yaml:"gateway6" json:"gateway6"`
	DHCP4       bool     `yaml:"dhcp4" json:"dhcp4"`
	DHCP6       bool     `yaml:"dhcp6" json:"dhcp6"`
	Optional    bool     `yaml:"optional" json:"optional"`
	MTU         int      `yaml:"mtu" json:"mtu"`
	Nameservers struct {
		Addresses []string `yaml:"addresses" json:"addresses"`
		Search    []string `yaml:"search" json:"search"`
	} `yaml:"nameservers" json:"nameservers"`
}

func unmarshalJSON(data []byte, v interface{}, strict bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	return dec.Decode(v)
}

func unmarshalYAML(data []byte, v interface{}, strict bool) error {
	if strict {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		err := dec.Decode(v)
		if err == io.EOF {
			return nil
		}
		return err
	}
	return yaml.Unmarshal(data, v)
}

// MetaData holds cloud-provided instance metadata from the NoCloud meta-data
// file. The instance-id field is required by the NoCloud spec. local-hostname
// (or hostname) may be used as a fallback hostname when user-data does not
// specify one.
type MetaData struct {
	InstanceID    string `yaml:"instance-id" json:"instance-id"`
	LocalHostname string `yaml:"local-hostname" json:"local-hostname"`
	Hostname      string `yaml:"hostname" json:"hostname"`
}

func UnmarshalMetaData(data []byte, md *MetaData, strict bool) error {
	yamlErr := unmarshalYAML(data, md, strict)
	if yamlErr == nil {
		return nil
	}
	if err := unmarshalJSON(data, md, strict); err == nil {
		return nil
	} else {
		return fmt.Errorf("yaml: %v; json: %v", yamlErr, err)
	}
}

func UnmarshalUserData(data []byte, ud *UserData, strict bool) error {
	yamlErr := unmarshalYAML(data, ud, strict)
	if yamlErr == nil {
		return nil
	}
	if err := unmarshalJSON(data, ud, strict); err == nil {
		return nil
	} else {
		return fmt.Errorf("yaml: %v; json: %v", yamlErr, err)
	}
}

func UnmarshalNetworkConfig(data []byte, nc *NetworkConfig, strict bool) error {
	yamlErr := unmarshalYAML(data, nc, strict)
	if yamlErr == nil {
		return nil
	}
	if err := unmarshalJSON(data, nc, strict); err == nil {
		return nil
	} else {
		return fmt.Errorf("yaml: %v; json: %v", yamlErr, err)
	}
}
