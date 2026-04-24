package types

import (
	"os"
	"strings"
	"testing"
)

func TestUnmarshalUserData(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    UserData
		wantErr bool
	}{
		{
			// Proxmox-style NoCloud user-data fixture.
			// Verifies: #cloud-config header treated as YAML comment, $5$ password
			// hash preserved verbatim, chpasswd.expire: False (capital-F) parsed as
			// bool false, unknown field package_upgrade silently ignored.
			name:  "proxmox user-data",
			input: mustReadFile(t, "testdata/proxmox-user-data.yaml"),
			want: UserData{
				Hostname:       "test-vm-01",
				FQDN:           "test-vm-01.example.com",
				ManageEtcHosts: true,
				User:           "testuser",
				Password:       "$5$testsalt$fakehashedpasswordfortestingpurposes",
				Users:          []string{"default"},
			},
		},
		{
			name:  "yaml hostname only",
			input: "hostname: myhost\n",
			want:  UserData{Hostname: "myhost"},
		},
		{
			name:  "yaml manage_etc_hosts false by default",
			input: "hostname: myhost\n",
			want:  UserData{Hostname: "myhost", ManageEtcHosts: false},
		},
		{
			name: "yaml full",
			input: `hostname: myhost
fqdn: myhost.example.com
user: ubuntu
password: $6$saltsalt$hash
manage_etc_hosts: true
`,
			want: UserData{
				Hostname:       "myhost",
				FQDN:           "myhost.example.com",
				User:           "ubuntu",
				Password:       "$6$saltsalt$hash",
				ManageEtcHosts: true,
			},
		},
		{
			name:  "json hostname and fqdn",
			input: `{"hostname":"myhost","fqdn":"myhost.example.com"}`,
			want:  UserData{Hostname: "myhost", FQDN: "myhost.example.com"},
		},
		{
			name:  "json full",
			input: `{"hostname":"myhost","user":"ubuntu","password":"secret","manage_etc_hosts":true}`,
			want:  UserData{Hostname: "myhost", User: "ubuntu", Password: "secret", ManageEtcHosts: true},
		},
		{
			name:    "invalid input",
			input:   "}{:::not yaml or json:::",
			wantErr: true,
		},
		{
			name:  "empty input yields zero value",
			input: "",
			want:  UserData{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ud UserData
			err := UnmarshalUserData([]byte(tt.input), &ud)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalUserData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ud.Hostname != tt.want.Hostname {
				t.Errorf("Hostname = %q, want %q", ud.Hostname, tt.want.Hostname)
			}
			if ud.FQDN != tt.want.FQDN {
				t.Errorf("FQDN = %q, want %q", ud.FQDN, tt.want.FQDN)
			}
			if ud.User != tt.want.User {
				t.Errorf("User = %q, want %q", ud.User, tt.want.User)
			}
			if ud.Password != tt.want.Password {
				t.Errorf("Password = %q, want %q", ud.Password, tt.want.Password)
			}
			if ud.ManageEtcHosts != tt.want.ManageEtcHosts {
				t.Errorf("ManageEtcHosts = %v, want %v", ud.ManageEtcHosts, tt.want.ManageEtcHosts)
			}
			if ud.Chpasswd.Expire != tt.want.Chpasswd.Expire {
				t.Errorf("Chpasswd.Expire = %v, want %v", ud.Chpasswd.Expire, tt.want.Chpasswd.Expire)
			}
			if len(ud.Users) != len(tt.want.Users) {
				t.Errorf("len(Users) = %d, want %d", len(ud.Users), len(tt.want.Users))
			} else {
				for i := range tt.want.Users {
					if ud.Users[i] != tt.want.Users[i] {
						t.Errorf("Users[%d] = %q, want %q", i, ud.Users[i], tt.want.Users[i])
					}
				}
			}
		})
	}
}

func TestUnmarshalNetworkConfig(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantVersion  int
		wantTypes    []string // expected v1 Config entry types (empty for v2)
		wantPhysical *physicalWant
		wantNS       *nameserverWant
		wantV2       *v2Want
		wantErr      bool
	}{
		{
			// Proxmox-style v1 network-config fixture: static IP, netmask,
			// gateway, nameserver address, and search domain.
			name:        "proxmox network-config v1 static",
			input:       mustReadFile(t, "testdata/proxmox-network-config.yaml"),
			wantVersion: 1,
			wantTypes:   []string{"physical", "nameserver"},
			wantPhysical: &physicalWant{
				name:       "eth0",
				mac:        "52:54:00:ab:cd:ef",
				subnetType: "static",
				address:    "192.0.2.10",
				netmask:    "255.255.255.0",
				gateway:    "192.0.2.1",
			},
			wantNS: &nameserverWant{
				addresses: []string{"192.0.2.1"},
				search:    []string{"example.com"},
			},
		},
		{
			name: "v1 yaml dhcp",
			input: `version: 1
config:
  - type: physical
    name: eth0
    mac_address: "aa:bb:cc:dd:ee:ff"
    subnets:
      - type: dhcp4
`,
			wantVersion: 1,
			wantTypes:   []string{"physical"},
			wantPhysical: &physicalWant{
				name:       "eth0",
				mac:        "aa:bb:cc:dd:ee:ff",
				subnetType: "dhcp4",
			},
		},
		{
			name:        "v1 json minimal",
			input:       `{"version":1,"config":[{"type":"physical","name":"eth0","mac_address":"aa:bb:cc:dd:ee:ff","subnets":[]}]}`,
			wantVersion: 1,
			wantTypes:   []string{"physical"},
		},
		{
			// v2 static: Ethernets map populated, Config empty.
			// Verifies CIDR address, gateway4, per-interface nameservers and search.
			name:        "v2 static from testdata",
			input:       mustReadFile(t, "testdata/nocloud-network-v2-static.yaml"),
			wantVersion: 2,
			wantTypes:   []string{},
			wantV2: &v2Want{
				key:       "eth0",
				setName:   "eth0",
				mac:       "52:54:00:ab:cd:ef",
				addresses: []string{"192.0.2.10/24"},
				gateway4:  "192.0.2.1",
				nsAddrs:   []string{"192.0.2.1"},
				nsSearch:  []string{"example.com"},
			},
		},
		{
			// v2 dhcp: DHCP4 true, no addresses or gateway.
			name:        "v2 dhcp from testdata",
			input:       mustReadFile(t, "testdata/nocloud-network-v2-dhcp.yaml"),
			wantVersion: 2,
			wantTypes:   []string{},
			wantV2: &v2Want{
				key:   "eth0",
				mac:   "52:54:00:ab:cd:ef",
				dhcp4: true,
			},
		},
		{
			name:    "invalid input",
			input:   "}{:::not yaml or json:::",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nc NetworkConfig
			err := UnmarshalNetworkConfig([]byte(tt.input), &nc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalNetworkConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if nc.Version != tt.wantVersion {
				t.Errorf("Version = %d, want %d", nc.Version, tt.wantVersion)
			}
			if len(nc.Config) != len(tt.wantTypes) {
				t.Fatalf("len(Config) = %d, want %d", len(nc.Config), len(tt.wantTypes))
			}
			for i, wantType := range tt.wantTypes {
				if nc.Config[i].Type != wantType {
					t.Errorf("Config[%d].Type = %q, want %q", i, nc.Config[i].Type, wantType)
				}
			}
			if tt.wantPhysical != nil {
				p := nc.Config[0]
				if p.Name != tt.wantPhysical.name {
					t.Errorf("physical.Name = %q, want %q", p.Name, tt.wantPhysical.name)
				}
				if p.MacAddress != tt.wantPhysical.mac {
					t.Errorf("physical.MacAddress = %q, want %q", p.MacAddress, tt.wantPhysical.mac)
				}
				if len(p.Subnets) > 0 {
					s := p.Subnets[0]
					if s.Type != tt.wantPhysical.subnetType {
						t.Errorf("subnet.Type = %q, want %q", s.Type, tt.wantPhysical.subnetType)
					}
					if tt.wantPhysical.address != "" && s.Address != tt.wantPhysical.address {
						t.Errorf("subnet.Address = %q, want %q", s.Address, tt.wantPhysical.address)
					}
					if tt.wantPhysical.netmask != "" && s.Netmask != tt.wantPhysical.netmask {
						t.Errorf("subnet.Netmask = %q, want %q", s.Netmask, tt.wantPhysical.netmask)
					}
					if tt.wantPhysical.gateway != "" && s.Gateway != tt.wantPhysical.gateway {
						t.Errorf("subnet.Gateway = %q, want %q", s.Gateway, tt.wantPhysical.gateway)
					}
				}
			}
			if tt.wantNS != nil {
				ns := nc.Config[len(nc.Config)-1]
				for i, addr := range tt.wantNS.addresses {
					if i >= len(ns.Address) || ns.Address[i] != addr {
						t.Errorf("nameserver.Address[%d] = %q, want %q", i, ns.Address[i], addr)
					}
				}
				for i, s := range tt.wantNS.search {
					if i >= len(ns.Search) || ns.Search[i] != s {
						t.Errorf("nameserver.Search[%d] = %q, want %q", i, ns.Search[i], s)
					}
				}
			}
			if tt.wantV2 != nil {
				eth, ok := nc.Ethernets[tt.wantV2.key]
				if !ok {
					t.Fatalf("Ethernets[%q] not found", tt.wantV2.key)
				}
				if tt.wantV2.setName != "" && eth.SetName != tt.wantV2.setName {
					t.Errorf("SetName = %q, want %q", eth.SetName, tt.wantV2.setName)
				}
				if eth.Match.MACAddress != tt.wantV2.mac {
					t.Errorf("Match.MACAddress = %q, want %q", eth.Match.MACAddress, tt.wantV2.mac)
				}
				if eth.DHCP4 != tt.wantV2.dhcp4 {
					t.Errorf("DHCP4 = %v, want %v", eth.DHCP4, tt.wantV2.dhcp4)
				}
				if len(eth.Addresses) != len(tt.wantV2.addresses) {
					t.Errorf("len(Addresses) = %d, want %d", len(eth.Addresses), len(tt.wantV2.addresses))
				} else {
					for i, a := range tt.wantV2.addresses {
						if eth.Addresses[i] != a {
							t.Errorf("Addresses[%d] = %q, want %q", i, eth.Addresses[i], a)
						}
					}
				}
				if tt.wantV2.gateway4 != "" && eth.Gateway4 != tt.wantV2.gateway4 {
					t.Errorf("Gateway4 = %q, want %q", eth.Gateway4, tt.wantV2.gateway4)
				}
				for i, a := range tt.wantV2.nsAddrs {
					if i >= len(eth.Nameservers.Addresses) || eth.Nameservers.Addresses[i] != a {
						t.Errorf("Nameservers.Addresses[%d] = %q, want %q", i, eth.Nameservers.Addresses[i], a)
					}
				}
				for i, s := range tt.wantV2.nsSearch {
					if i >= len(eth.Nameservers.Search) || eth.Nameservers.Search[i] != s {
						t.Errorf("Nameservers.Search[%d] = %q, want %q", i, eth.Nameservers.Search[i], s)
					}
				}
			}
		})
	}
}

type physicalWant struct {
	name, mac, subnetType, address, netmask, gateway string
}

type nameserverWant struct {
	addresses []string
	search    []string
}

type v2Want struct {
	key, setName, mac, gateway4 string
	addresses                   []string
	dhcp4                       bool
	nsAddrs                     []string
	nsSearch                    []string
}

// TestUnmarshalNetworkConfig_MultiNIC verifies parsing of a Proxmox-style
// network-config with two physical interfaces (one DHCP, one static) plus a
// nameserver entry.
func TestUnmarshalNetworkConfig_MultiNIC(t *testing.T) {
	var nc NetworkConfig
	if err := UnmarshalNetworkConfig([]byte(mustReadFile(t, "testdata/proxmox-network-config-multi-nic.yaml")), &nc); err != nil {
		t.Fatalf("UnmarshalNetworkConfig() error = %v", err)
	}

	if nc.Version != 1 {
		t.Fatalf("Version = %d, want 1", nc.Version)
	}
	if len(nc.Config) != 3 {
		t.Fatalf("len(Config) = %d, want 3 (eth0, eth1, nameserver)", len(nc.Config))
	}

	// eth0 — DHCP
	eth0 := nc.Config[0]
	if eth0.Type != "physical" || eth0.Name != "eth0" || eth0.MacAddress != "52:54:00:11:22:33" {
		t.Errorf("eth0 = {%s %s %s}, want {physical eth0 52:54:00:11:22:33}", eth0.Type, eth0.Name, eth0.MacAddress)
	}
	if len(eth0.Subnets) == 0 || eth0.Subnets[0].Type != "dhcp4" {
		t.Errorf("eth0 subnet type = %q, want dhcp4", eth0.Subnets[0].Type)
	}

	// eth1 — static
	eth1 := nc.Config[1]
	if eth1.Type != "physical" || eth1.Name != "eth1" || eth1.MacAddress != "52:54:00:44:55:66" {
		t.Errorf("eth1 = {%s %s %s}, want {physical eth1 52:54:00:44:55:66}", eth1.Type, eth1.Name, eth1.MacAddress)
	}
	if len(eth1.Subnets) == 0 {
		t.Fatal("eth1 has no subnets")
	}
	s := eth1.Subnets[0]
	if s.Type != "static" || s.Address != "198.51.100.10" || s.Netmask != "255.255.255.0" || s.Gateway != "198.51.100.1" {
		t.Errorf("eth1 subnet = {%s %s %s %s}, want {static 198.51.100.10 255.255.255.0 198.51.100.1}", s.Type, s.Address, s.Netmask, s.Gateway)
	}

	// nameserver
	ns := nc.Config[2]
	if ns.Type != "nameserver" {
		t.Errorf("Config[2].Type = %q, want nameserver", ns.Type)
	}
	if len(ns.Address) == 0 || ns.Address[0] != "192.0.2.1" {
		t.Errorf("nameserver address = %v, want [192.0.2.1]", ns.Address)
	}
	if len(ns.Search) == 0 || ns.Search[0] != "example.com" {
		t.Errorf("nameserver search = %v, want [example.com]", ns.Search)
	}
}

// TestUnmarshalUserData_ErrorContainsBothFormats verifies that when input is
// neither valid YAML nor valid JSON, the error message includes both errors.
func TestUnmarshalUserData_ErrorContainsBothFormats(t *testing.T) {
	var ud UserData
	err := UnmarshalUserData([]byte("}{:::not yaml or json:::"), &ud)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "yaml:") {
		t.Errorf("error %q does not contain \"yaml:\"", msg)
	}
	if !strings.Contains(msg, "json:") {
		t.Errorf("error %q does not contain \"json:\"", msg)
	}
}

// TestUnmarshalNetworkConfig_ErrorContainsBothFormats verifies that when input
// is neither valid YAML nor valid JSON, the error message includes both errors.
func TestUnmarshalNetworkConfig_ErrorContainsBothFormats(t *testing.T) {
	var nc NetworkConfig
	err := UnmarshalNetworkConfig([]byte("}{:::not yaml or json:::"), &nc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "yaml:") {
		t.Errorf("error %q does not contain \"yaml:\"", msg)
	}
	if !strings.Contains(msg, "json:") {
		t.Errorf("error %q does not contain \"json:\"", msg)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read testdata file %q: %v", path, err)
	}
	return string(b)
}
