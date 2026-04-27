package types

import (
	"os"
	"reflect"
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
				Users:          UserList{{Name: "default"}},
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
		{
			// Verify that chpasswd.expire parses as true (the false / default is
			// exercised indirectly by several other cases).
			name:  "yaml chpasswd expire true",
			input: "hostname: myhost\nchpasswd:\n  expire: true\n",
			want: UserData{
				Hostname: "myhost",
				Chpasswd: struct {
					Expire bool     `yaml:"expire" json:"expire"`
					List   []string `yaml:"list" json:"list"`
				}{Expire: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ud UserData
			err := UnmarshalUserData([]byte(tt.input), &ud, false)
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
			if !reflect.DeepEqual(ud.Users, tt.want.Users) {
				t.Errorf("Users = %+v, want %+v", ud.Users, tt.want.Users)
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
			err := UnmarshalNetworkConfig([]byte(tt.input), &nc, false)
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
	if err := UnmarshalNetworkConfig([]byte(mustReadFile(t, "testdata/proxmox-network-config-multi-nic.yaml")), &nc, false); err != nil {
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
	err := UnmarshalUserData([]byte("}{:::not yaml or json:::"), &ud, false)
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
	err := UnmarshalNetworkConfig([]byte("}{:::not yaml or json:::"), &nc, false)
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

// TestUnmarshalStrict verifies that strict=true rejects unknown YAML fields
// and that strict=false continues to accept them.
func TestUnmarshalStrict(t *testing.T) {
	withUnknown := mustReadFile(t, "testdata/proxmox-user-data.yaml")

	t.Run("user-data strict rejects unknown fields", func(t *testing.T) {
		var ud UserData
		if err := UnmarshalUserData([]byte(withUnknown), &ud, true); err == nil {
			t.Fatal("expected error for unknown field in strict mode, got nil")
		}
	})

	t.Run("user-data non-strict accepts unknown fields", func(t *testing.T) {
		var ud UserData
		if err := UnmarshalUserData([]byte(withUnknown), &ud, false); err != nil {
			t.Fatalf("unexpected error in non-strict mode: %v", err)
		}
		if ud.Hostname != "test-vm-01" {
			t.Errorf("Hostname = %q, want %q", ud.Hostname, "test-vm-01")
		}
	})

	t.Run("network-config strict accepts clean YAML", func(t *testing.T) {
		input := mustReadFile(t, "testdata/proxmox-network-config.yaml")
		var nc NetworkConfig
		if err := UnmarshalNetworkConfig([]byte(input), &nc, true); err != nil {
			t.Fatalf("unexpected error for clean YAML in strict mode: %v", err)
		}
		if nc.Version != 1 {
			t.Errorf("Version = %d, want 1", nc.Version)
		}
	})

	t.Run("network-config strict rejects unknown YAML fields", func(t *testing.T) {
		input := `version: 1
config:
  - type: physical
    name: eth0
    extra_unknown_key: surprise
`
		var nc NetworkConfig
		if err := UnmarshalNetworkConfig([]byte(input), &nc, true); err == nil {
			t.Fatal("expected error for unknown field in strict mode, got nil")
		}
	})

	// JSON strict tests — previously json.Unmarshal was used unconditionally,
	// so unknown fields were always accepted regardless of the strict flag.
	t.Run("user-data strict rejects unknown JSON fields", func(t *testing.T) {
		input := `{"hostname":"myhost","unknown_field":"surprise"}`
		var ud UserData
		if err := UnmarshalUserData([]byte(input), &ud, true); err == nil {
			t.Fatal("expected error for unknown JSON field in strict mode, got nil")
		}
	})

	t.Run("user-data non-strict accepts unknown JSON fields", func(t *testing.T) {
		input := `{"hostname":"myhost","unknown_field":"surprise"}`
		var ud UserData
		if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
			t.Fatalf("unexpected error in non-strict mode: %v", err)
		}
		if ud.Hostname != "myhost" {
			t.Errorf("Hostname = %q, want %q", ud.Hostname, "myhost")
		}
	})

	t.Run("network-config strict rejects unknown JSON fields", func(t *testing.T) {
		input := `{"version":1,"config":[],"unknown_field":"surprise"}`
		var nc NetworkConfig
		if err := UnmarshalNetworkConfig([]byte(input), &nc, true); err == nil {
			t.Fatal("expected error for unknown JSON field in strict mode, got nil")
		}
	})
}

// TestUnmarshalNetworkConfig_EmptyInput verifies that an empty byte slice
// yields a zero-value NetworkConfig without an error, mirroring the behaviour
// of UnmarshalUserData for the same input.
func TestUnmarshalNetworkConfig_EmptyInput(t *testing.T) {
	var nc NetworkConfig
	if err := UnmarshalNetworkConfig([]byte(""), &nc, false); err != nil {
		t.Fatalf("UnmarshalNetworkConfig() unexpected error: %v", err)
	}
	if nc.Version != 0 {
		t.Errorf("Version = %d, want 0", nc.Version)
	}
	if len(nc.Config) != 0 {
		t.Errorf("len(Config) = %d, want 0", len(nc.Config))
	}
	if len(nc.Ethernets) != 0 {
		t.Errorf("len(Ethernets) = %d, want 0", len(nc.Ethernets))
	}
}

func TestUnmarshalMetaData(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    MetaData
		wantErr bool
	}{
		{
			name:  "full fixture",
			input: mustReadFile(t, "testdata/nocloud-meta-data.yaml"),
			want: MetaData{
				InstanceID:    "iid-local01",
				LocalHostname: "myvm",
				Hostname:      "myvm.example.com",
			},
		},
		{
			name:  "instance-id only",
			input: "instance-id: iid-abcdefg\n",
			want:  MetaData{InstanceID: "iid-abcdefg"},
		},
		{
			name:  "local-hostname only",
			input: "instance-id: iid-x\nlocal-hostname: myhost\n",
			want:  MetaData{InstanceID: "iid-x", LocalHostname: "myhost"},
		},
		{
			name:  "hostname only (no local-hostname)",
			input: "instance-id: iid-x\nhostname: myhost\n",
			want:  MetaData{InstanceID: "iid-x", Hostname: "myhost"},
		},
		{
			name:  "json format",
			input: `{"instance-id":"iid-json","local-hostname":"jsonhost"}`,
			want:  MetaData{InstanceID: "iid-json", LocalHostname: "jsonhost"},
		},
		{
			name:  "empty input yields zero value",
			input: "",
			want:  MetaData{},
		},
		{
			name:    "invalid input",
			input:   "}{:::not yaml or json:::",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var md MetaData
			err := UnmarshalMetaData([]byte(tt.input), &md, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalMetaData() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if md.InstanceID != tt.want.InstanceID {
				t.Errorf("InstanceID = %q, want %q", md.InstanceID, tt.want.InstanceID)
			}
			if md.LocalHostname != tt.want.LocalHostname {
				t.Errorf("LocalHostname = %q, want %q", md.LocalHostname, tt.want.LocalHostname)
			}
			if md.Hostname != tt.want.Hostname {
				t.Errorf("Hostname = %q, want %q", md.Hostname, tt.want.Hostname)
			}
		})
	}
}

func mustReadFile(t *testing.T, path string) string {	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read testdata file %q: %v", path, err)
	}
	return string(b)
}

func TestUnmarshalUserDataWriteFiles(t *testing.T) {
	input := `#cloud-config
hostname: myhost
write_files:
  - path: /etc/myapp.conf
    content: |
      key=value
    permissions: "0644"
  - path: /usr/local/bin/script.sh
    content: aGVsbG8=
    encoding: b64
    permissions: "0755"
    append: true
`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if ud.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", ud.Hostname, "myhost")
	}
	if len(ud.WriteFiles) != 2 {
		t.Fatalf("len(WriteFiles) = %d, want 2", len(ud.WriteFiles))
	}

	f0 := ud.WriteFiles[0]
	if f0.Path != "/etc/myapp.conf" {
		t.Errorf("WriteFiles[0].Path = %q, want %q", f0.Path, "/etc/myapp.conf")
	}
	if f0.Content != "key=value\n" {
		t.Errorf("WriteFiles[0].Content = %q, want %q", f0.Content, "key=value\n")
	}
	if f0.Permissions != "0644" {
		t.Errorf("WriteFiles[0].Permissions = %q, want %q", f0.Permissions, "0644")
	}
	if f0.Append {
		t.Errorf("WriteFiles[0].Append = true, want false")
	}

	f1 := ud.WriteFiles[1]
	if f1.Path != "/usr/local/bin/script.sh" {
		t.Errorf("WriteFiles[1].Path = %q, want %q", f1.Path, "/usr/local/bin/script.sh")
	}
	if f1.Encoding != "b64" {
		t.Errorf("WriteFiles[1].Encoding = %q, want %q", f1.Encoding, "b64")
	}
	if f1.Permissions != "0755" {
		t.Errorf("WriteFiles[1].Permissions = %q, want %q", f1.Permissions, "0755")
	}
	if !f1.Append {
		t.Errorf("WriteFiles[1].Append = false, want true")
	}
}

func TestUnmarshalUserDataWriteFilesJSON(t *testing.T) {
	input := `{"hostname":"myhost","write_files":[{"path":"/etc/test.conf","content":"hello","permissions":"0600"}]}`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.WriteFiles) != 1 {
		t.Fatalf("len(WriteFiles) = %d, want 1", len(ud.WriteFiles))
	}
	if ud.WriteFiles[0].Path != "/etc/test.conf" {
		t.Errorf("Path = %q, want %q", ud.WriteFiles[0].Path, "/etc/test.conf")
	}
	if ud.WriteFiles[0].Content != "hello" {
		t.Errorf("Content = %q, want %q", ud.WriteFiles[0].Content, "hello")
	}
	if ud.WriteFiles[0].Permissions != "0600" {
		t.Errorf("Permissions = %q, want %q", ud.WriteFiles[0].Permissions, "0600")
	}
}

func TestUnmarshalUserDataRuncmd(t *testing.T) {
	input := `#cloud-config
runcmd:
  - echo hello
  - [touch, /tmp/runcmd-test]
  - sh -c "echo world"
`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Runcmd) != 3 {
		t.Fatalf("len(Runcmd) = %d, want 3", len(ud.Runcmd))
	}
	if ud.Runcmd[0].Shell != "echo hello" {
		t.Errorf("Runcmd[0].Shell = %q, want %q", ud.Runcmd[0].Shell, "echo hello")
	}
	if ud.Runcmd[0].Args != nil {
		t.Errorf("Runcmd[0].Args should be nil for shell item")
	}
	if len(ud.Runcmd[1].Args) != 2 || ud.Runcmd[1].Args[0] != "touch" || ud.Runcmd[1].Args[1] != "/tmp/runcmd-test" {
		t.Errorf("Runcmd[1].Args = %v, want [touch /tmp/runcmd-test]", ud.Runcmd[1].Args)
	}
	if ud.Runcmd[1].Shell != "" {
		t.Errorf("Runcmd[1].Shell should be empty for exec item")
	}
	if ud.Runcmd[2].Shell != `sh -c "echo world"` {
		t.Errorf("Runcmd[2].Shell = %q, want %q", ud.Runcmd[2].Shell, `sh -c "echo world"`)
	}
}

func TestUnmarshalUserDataRuncmdJSON(t *testing.T) {
	input := `{"runcmd":["echo hello",["touch","/tmp/x"]]}`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Runcmd) != 2 {
		t.Fatalf("len(Runcmd) = %d, want 2", len(ud.Runcmd))
	}
	if ud.Runcmd[0].Shell != "echo hello" {
		t.Errorf("Runcmd[0].Shell = %q, want %q", ud.Runcmd[0].Shell, "echo hello")
	}
	if len(ud.Runcmd[1].Args) != 2 {
		t.Errorf("Runcmd[1].Args = %v, want [touch /tmp/x]", ud.Runcmd[1].Args)
	}
}

func TestUnmarshalGroupsString(t *testing.T) {
	input := "groups: sudo, docker\n"
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(ud.Groups))
	}
	if ud.Groups[0].Name != "sudo" {
		t.Errorf("Groups[0].Name = %q, want %q", ud.Groups[0].Name, "sudo")
	}
	if ud.Groups[1].Name != "docker" {
		t.Errorf("Groups[1].Name = %q, want %q", ud.Groups[1].Name, "docker")
	}
}

func TestUnmarshalGroupsList(t *testing.T) {
	input := `#cloud-config
groups:
  - admins
  - developers: alice
  - ops: [bob, carol]
`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Groups) != 3 {
		t.Fatalf("len(Groups) = %d, want 3", len(ud.Groups))
	}
	if ud.Groups[0].Name != "admins" || len(ud.Groups[0].Members) != 0 {
		t.Errorf("Groups[0] = %+v, want {Name:admins Members:[]}", ud.Groups[0])
	}
	if ud.Groups[1].Name != "developers" || len(ud.Groups[1].Members) != 1 || ud.Groups[1].Members[0] != "alice" {
		t.Errorf("Groups[1] = %+v, want {Name:developers Members:[alice]}", ud.Groups[1])
	}
	if ud.Groups[2].Name != "ops" || len(ud.Groups[2].Members) != 2 {
		t.Errorf("Groups[2] = %+v, want {Name:ops Members:[bob carol]}", ud.Groups[2])
	}
}

func TestUnmarshalGroupsJSON(t *testing.T) {
	input := `{"groups":["wheel",{"devs":["alice","bob"]}]}`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(ud.Groups))
	}
	if ud.Groups[0].Name != "wheel" {
		t.Errorf("Groups[0].Name = %q, want %q", ud.Groups[0].Name, "wheel")
	}
	if ud.Groups[1].Name != "devs" || len(ud.Groups[1].Members) != 2 {
		t.Errorf("Groups[1] = %+v, want {Name:devs Members:[alice bob]}", ud.Groups[1])
	}
}

func TestUnmarshalUsersListMixed(t *testing.T) {
	input := `#cloud-config
users:
  - default
  - name: alice
    gecos: Alice Wonderland
    groups: sudo, docker
    shell: /bin/bash
    hashed_passwd: "$6$salt$hash"
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - ssh-rsa AAAA...
`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Users) != 2 {
		t.Fatalf("len(Users) = %d, want 2", len(ud.Users))
	}
	if ud.Users[0].Name != "default" {
		t.Errorf("Users[0].Name = %q, want %q", ud.Users[0].Name, "default")
	}
	alice := ud.Users[1]
	if alice.Name != "alice" {
		t.Errorf("alice.Name = %q, want %q", alice.Name, "alice")
	}
	if alice.Gecos != "Alice Wonderland" {
		t.Errorf("alice.Gecos = %q, want %q", alice.Gecos, "Alice Wonderland")
	}
	if len(alice.Groups) != 2 || alice.Groups[0] != "sudo" || alice.Groups[1] != "docker" {
		t.Errorf("alice.Groups = %v, want [sudo docker]", alice.Groups)
	}
	if alice.Shell != "/bin/bash" {
		t.Errorf("alice.Shell = %q, want %q", alice.Shell, "/bin/bash")
	}
	if alice.Sudo != "ALL=(ALL) NOPASSWD:ALL" {
		t.Errorf("alice.Sudo = %q, want %q", alice.Sudo, "ALL=(ALL) NOPASSWD:ALL")
	}
	if len(alice.SSHAuthorizedKeys) != 1 {
		t.Errorf("alice.SSHAuthorizedKeys = %v, want 1 key", alice.SSHAuthorizedKeys)
	}
}

func TestUnmarshalUsersJSON(t *testing.T) {
	input := `{"users":["default",{"name":"bob","shell":"/bin/sh","groups":["wheel"]}]}`
	var ud UserData
	if err := UnmarshalUserData([]byte(input), &ud, false); err != nil {
		t.Fatalf("UnmarshalUserData() error = %v", err)
	}
	if len(ud.Users) != 2 {
		t.Fatalf("len(Users) = %d, want 2", len(ud.Users))
	}
	if ud.Users[0].Name != "default" {
		t.Errorf("Users[0].Name = %q, want %q", ud.Users[0].Name, "default")
	}
	if ud.Users[1].Name != "bob" {
		t.Errorf("Users[1].Name = %q, want %q", ud.Users[1].Name, "bob")
	}
	if len(ud.Users[1].Groups) != 1 || ud.Users[1].Groups[0] != "wheel" {
		t.Errorf("Users[1].Groups = %v, want [wheel]", ud.Users[1].Groups)
	}
}
