package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/demicloud/nocloud-init/internal/types"
)

func TestNetmaskToCIDR(t *testing.T) {
	tests := []struct {
		netmask string
		want    int
		wantErr bool
	}{
		{"255.255.255.0", 24, false},
		{"255.255.0.0", 16, false},
		{"255.0.0.0", 8, false},
		{"255.255.255.128", 25, false},
		{"255.255.255.252", 30, false},
		{"0.0.0.0", 0, false},
		{"255.255.255.255", 32, false},
		{"not-a-mask", 0, true},
		{"", 0, true},
		{"999.999.999.999", 0, true},
		// non-contiguous mask must be rejected
		{"255.0.255.0", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.netmask, func(t *testing.T) {
			got, err := netmaskToCIDR(tt.netmask)
			if (err != nil) != tt.wantErr {
				t.Fatalf("netmaskToCIDR(%q) error = %v, wantErr %v", tt.netmask, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("netmaskToCIDR(%q) = %d, want %d", tt.netmask, got, tt.want)
			}
		})
	}
}

func TestParseCIDRAddress(t *testing.T) {
	tests := []struct {
		input   string
		wantIP  string
		wantPfx int
		wantErr bool
	}{
		// RFC 5737 documentation addresses
		{"192.0.2.10/24", "192.0.2.10", 24, false},
		{"198.51.100.10/24", "198.51.100.10", 24, false},
		{"203.0.113.1/8", "203.0.113.1", 8, false},
		// netmask notation fallback
		{"192.0.2.10/255.255.255.0", "192.0.2.10", 24, false},
		// invalid
		{"not-an-address", "", 0, true},
		{"192.0.2.10", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip, pfx, err := parseCIDRAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCIDRAddress(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ip != tt.wantIP {
				t.Errorf("ip = %q, want %q", ip, tt.wantIP)
			}
			if pfx != tt.wantPfx {
				t.Errorf("prefix = %d, want %d", pfx, tt.wantPfx)
			}
		})
	}
}

func TestGenerateSystemdNetworkConfig_V1Static(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "52:54:00:ab:cd:ef",
				Subnets: []types.NetworkConfigV1Subnet{
					{Type: "static", Address: "192.0.2.10", Netmask: "255.255.255.0", Gateway: "192.0.2.1"},
				},
			},
			{
				Type:    "nameserver",
				Address: []string{"192.0.2.1"},
				Search:  []string{"example.com"},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "MACAddress=52:54:00:ab:cd:ef")
	assertFileContains(t, networkFile, "Address=192.0.2.10/24")
	assertFileContains(t, networkFile, "Gateway=192.0.2.1")
	assertFileNotContains(t, networkFile, "DHCP=yes")

	linkFile := filepath.Join(dir, "10-cloud-init-eth0.link")
	assertFileContains(t, linkFile, "MACAddress=52:54:00:ab:cd:ef")
	assertFileContains(t, linkFile, "Name=eth0")

	assertFileContains(t, resolvPath, "nameserver 192.0.2.1")
	assertFileContains(t, resolvPath, "search example.com")
}

func TestGenerateSystemdNetworkConfig_V1DHCP(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets: []types.NetworkConfigV1Subnet{
					{Type: "dhcp4"},
				},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "DHCP=yes")
	assertFileNotContains(t, networkFile, "\nAddress=")
	assertFileNotContains(t, networkFile, "Gateway=")

	// resolv.conf must not be created when no nameservers are specified.
	if _, err := os.Stat(resolvPath); !os.IsNotExist(err) {
		t.Errorf("resolv.conf should not be created when no nameservers are present")
	}
}

func TestGenerateSystemdNetworkConfig_V2Static(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:     struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "52:54:00:ab:cd:ef"},
				SetName:   "eth0",
				Addresses: []string{"192.0.2.10/24"},
				Gateway4:  "192.0.2.1",
				Nameservers: struct {
					Addresses []string `yaml:"addresses" json:"addresses"`
					Search    []string `yaml:"search" json:"search"`
				}{
					Addresses: []string{"192.0.2.1"},
					Search:    []string{"example.com"},
				},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "MACAddress=52:54:00:ab:cd:ef")
	assertFileContains(t, networkFile, "Address=192.0.2.10/24")
	assertFileContains(t, networkFile, "Gateway=192.0.2.1")
	assertFileNotContains(t, networkFile, "DHCP=yes")

	linkFile := filepath.Join(dir, "10-cloud-init-eth0.link")
	assertFileContains(t, linkFile, "MACAddress=52:54:00:ab:cd:ef")
	assertFileContains(t, linkFile, "Name=eth0")

	assertFileContains(t, resolvPath, "nameserver 192.0.2.1")
	assertFileContains(t, resolvPath, "search example.com")
}

func TestGenerateSystemdNetworkConfig_V2DHCP(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:   struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "aa:bb:cc:dd:ee:ff"},
				SetName: "eth0",
				DHCP4:   true,
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "DHCP=yes")
	assertFileNotContains(t, networkFile, "\nAddress=")
}

func TestGenerateSystemdNetworkConfig_V2SetNameFallback(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	// set-name omitted: map key should be used as interface name
	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"enp3s0": {
				Match: struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "aa:bb:cc:dd:ee:ff"},
				DHCP4: true,
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	assertFileContains(t, filepath.Join(dir, "10-cloud-init-enp3s0.network"), "MACAddress=aa:bb:cc:dd:ee:ff")
	assertFileContains(t, filepath.Join(dir, "10-cloud-init-enp3s0.link"), "Name=enp3s0")
}

// TestGenerateSystemdNetworkConfig_V1MultiNIC verifies generation for a
// Proxmox-style config with two physical interfaces (eth0 DHCP, eth1 static)
// plus a shared nameserver entry.
func TestGenerateSystemdNetworkConfig_V1MultiNIC(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "52:54:00:11:22:33",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
			{
				Type:       "physical",
				Name:       "eth1",
				MacAddress: "52:54:00:44:55:66",
				Subnets: []types.NetworkConfigV1Subnet{
					{Type: "static", Address: "198.51.100.10", Netmask: "255.255.255.0", Gateway: "198.51.100.1"},
				},
			},
			{
				Type:    "nameserver",
				Address: []string{"192.0.2.1"},
				Search:  []string{"example.com"},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	// eth0 — DHCP
	eth0Net := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, eth0Net, "MACAddress=52:54:00:11:22:33")
	assertFileContains(t, eth0Net, "DHCP=yes")
	assertFileNotContains(t, eth0Net, "\nAddress=")
	assertFileContains(t, filepath.Join(dir, "10-cloud-init-eth0.link"), "Name=eth0")

	// eth1 — static
	eth1Net := filepath.Join(dir, "10-cloud-init-eth1.network")
	assertFileContains(t, eth1Net, "MACAddress=52:54:00:44:55:66")
	assertFileContains(t, eth1Net, "Address=198.51.100.10/24")
	assertFileContains(t, eth1Net, "Gateway=198.51.100.1")
	assertFileNotContains(t, eth1Net, "DHCP=yes")
	assertFileContains(t, filepath.Join(dir, "10-cloud-init-eth1.link"), "Name=eth1")

	// shared nameserver
	assertFileContains(t, resolvPath, "nameserver 192.0.2.1")
	assertFileContains(t, resolvPath, "search example.com")
}

// TestGenerateSystemdNetworkConfig_V1MultipleNameserverEntries verifies that
// two separate nameserver entries are merged rather than the last one winning.
func TestGenerateSystemdNetworkConfig_V1MultipleNameserverEntries(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
			{
				Type:    "nameserver",
				Address: []string{"192.0.2.1"},
				Search:  []string{"example.com"},
			},
			{
				Type:    "nameserver",
				Address: []string{"192.0.2.2"},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	// Both nameservers must appear — the second entry must not overwrite the first.
	assertFileContains(t, resolvPath, "nameserver 192.0.2.1")
	assertFileContains(t, resolvPath, "nameserver 192.0.2.2")
	// Search domain from the first nameserver entry must not be lost when a
	// second nameserver entry has no search domain.
	assertFileContains(t, resolvPath, "search example.com")
}

func TestGenerateSystemdNetworkConfig_V1InvalidMAC(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "not-a-mac",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid MAC address, got nil")
	}
	if !strings.Contains(err.Error(), "invalid MAC address") {
		t.Errorf("error %q should mention invalid MAC address", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_V2InvalidMAC(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:   struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "gg:hh:ii:jj:kk:ll"},
				SetName: "eth0",
				DHCP4:   true,
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid MAC address, got nil")
	}
	if !strings.Contains(err.Error(), "invalid MAC address") {
		t.Errorf("error %q should mention invalid MAC address", err.Error())
	}
}

func TestIsValidMACAddress(t *testing.T) {
	valid := []string{
		"52:54:00:ab:cd:ef",
		"AA:BB:CC:DD:EE:FF",
		"01-23-45-67-89-ab",
		"0123.4567.89ab",
	}
	for _, mac := range valid {
		if !isValidMACAddress(mac) {
			t.Errorf("isValidMACAddress(%q) = false, want true", mac)
		}
	}

	invalid := []string{
		"not-a-mac",
		"gg:hh:ii:jj:kk:ll",
		"52:54:00:ab:cd",
		"52:54:00:ab:cd:ef:00:extra",
		"",
	}
	for _, mac := range invalid {
		if isValidMACAddress(mac) {
			t.Errorf("isValidMACAddress(%q) = true, want false", mac)
		}
	}
}

func TestIsValidInterfaceName(t *testing.T) {
	valid := []string{"eth0", "enp3s0", "eth0:1", "eth_0", "eth-0", "lo", "wlan0"}
	for _, name := range valid {
		if !isValidInterfaceName(name) {
			t.Errorf("isValidInterfaceName(%q) = false, want true", name)
		}
	}

	invalid := []string{"", "../etc/passwd", "eth0/bad", "eth0\x00null", "eth0.1", "eth 0", "eth0!"}
	for _, name := range invalid {
		if isValidInterfaceName(name) {
			t.Errorf("isValidInterfaceName(%q) = true, want false", name)
		}
	}
}

func TestGenerateSystemdNetworkConfig_V1InvalidInterfaceName(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "../evil",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid interface name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid interface name") {
		t.Errorf("error %q should mention invalid interface name", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_V2InvalidInterfaceName(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"../evil": {
				Match: struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "aa:bb:cc:dd:ee:ff"},
				DHCP4: true,
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid interface name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid interface name") {
		t.Errorf("error %q should mention invalid interface name", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_V2InvalidSetName(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:   struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "aa:bb:cc:dd:ee:ff"},
				SetName: "../../etc/cron.d/evil",
				DHCP4:   true,
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid set-name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid interface name") {
		t.Errorf("error %q should mention invalid interface name", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{Version: 3}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error %q should mention unsupported version", err.Error())
	}
}

func TestUpdateResolvConfAt_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")

	if err := updateResolvConfAt(path, []string{"1.1.1.1", "8.8.8.8"}, "example.com"); err != nil {
		t.Fatalf("updateResolvConfAt() error = %v", err)
	}

	// Target must exist with expected content.
	assertFileContains(t, path, "nameserver 1.1.1.1")
	assertFileContains(t, path, "nameserver 8.8.8.8")
	assertFileContains(t, path, "search example.com")
	assertFileNotContains(t, path, "trust-ad")

	// No temp files must be left behind in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "resolv.conf" {
			t.Errorf("unexpected leftover file in dir: %s", e.Name())
		}
	}
}

func TestUpdateResolvConfAt_EmptySearchDomain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")

	if err := updateResolvConfAt(path, []string{"1.1.1.1"}, ""); err != nil {
		t.Fatalf("updateResolvConfAt() error = %v", err)
	}

	// No search line should appear when search domain is empty.
	assertFileNotContains(t, path, "search")
	assertFileContains(t, path, "nameserver 1.1.1.1")
	assertFileContains(t, path, "options edns0")
}

func TestUpdateResolvConfAt_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-resolv.conf")
	link := filepath.Join(dir, "resolv.conf")

	if err := os.WriteFile(target, []byte("# real\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := updateResolvConfAt(link, []string{"1.1.1.1"}, "example.com")
	if err == nil {
		t.Fatal("expected error for symlink target, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q should mention symlink", err.Error())
	}
}

// TestGenerateSystemdNetworkConfig_V2DuplicateNameservers verifies that when two
// interfaces share a nameserver, only one nameserver line appears in resolv.conf.
func TestGenerateSystemdNetworkConfig_V2DuplicateNameservers(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	sharedNS := struct {
		Addresses []string `yaml:"addresses" json:"addresses"`
		Search    []string `yaml:"search" json:"search"`
	}{
		Addresses: []string{"192.0.2.1"},
		Search:    []string{"example.com"},
	}

	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:       struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "52:54:00:11:22:33"},
				SetName:     "eth0",
				DHCP4:       true,
				Nameservers: sharedNS,
			},
			"eth1": {
				Match:       struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "52:54:00:44:55:66"},
				SetName:     "eth1",
				DHCP4:       true,
				Nameservers: sharedNS,
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	content, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("failed to read resolv.conf: %v", err)
	}
	got := string(content)

	// Exactly one nameserver line must appear for the shared address.
	count := strings.Count(got, "nameserver 192.0.2.1")
	if count != 1 {
		t.Errorf("expected exactly 1 occurrence of 'nameserver 192.0.2.1', got %d\n%s", count, got)
	}
}

// TestGenerateSystemdNetworkConfig_V1NoMAC verifies that when a v1 physical
// interface has no mac_address, the .network file matches by Name= and no
// .link file is created.
func TestGenerateSystemdNetworkConfig_V1NoMAC(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:    "physical",
				Name:    "eth0",
				Subnets: []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "Name=eth0")
	assertFileNotContains(t, networkFile, "MACAddress=")

	// No .link file must be created when there is no MAC to match on.
	linkFile := filepath.Join(dir, "10-cloud-init-eth0.link")
	if _, err := os.Stat(linkFile); !os.IsNotExist(err) {
		t.Errorf(".link file should not be created when MAC address is absent")
	}
}

// TestGenerateSystemdNetworkConfig_V2NoMAC verifies that when a v2 ethernet
// entry has no match.macaddress, the .network file matches by Name= and no
// .link file is created.
func TestGenerateSystemdNetworkConfig_V2NoMAC(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")

	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				SetName: "eth0",
				DHCP4:   true,
			},
		},
	}

	if err := generateSystemdNetworkConfigTo(config, dir, resolvPath); err != nil {
		t.Fatalf("generateSystemdNetworkConfigTo() error = %v", err)
	}

	networkFile := filepath.Join(dir, "10-cloud-init-eth0.network")
	assertFileContains(t, networkFile, "Name=eth0")
	assertFileNotContains(t, networkFile, "MACAddress=")

	// No .link file must be created when there is no MAC to match on.
	linkFile := filepath.Join(dir, "10-cloud-init-eth0.link")
	if _, err := os.Stat(linkFile); !os.IsNotExist(err) {
		t.Errorf(".link file should not be created when MAC address is absent")
	}
}

func TestGenerateSystemdNetworkConfig_V1InvalidAddress(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets: []types.NetworkConfigV1Subnet{
					{Type: "static", Address: "not-an-ip", Netmask: "255.255.255.0", Gateway: "192.0.2.1"},
				},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("error %q should mention invalid address", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_V1InvalidGateway(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets: []types.NetworkConfigV1Subnet{
					{Type: "static", Address: "192.0.2.10", Netmask: "255.255.255.0", Gateway: "not-an-ip"},
				},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid gateway, got nil")
	}
	if !strings.Contains(err.Error(), "invalid gateway") {
		t.Errorf("error %q should mention invalid gateway", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_V2InvalidGateway4(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 2,
		Ethernets: map[string]types.NetworkConfigV2Ethernet{
			"eth0": {
				Match:     struct{ MACAddress string `yaml:"macaddress" json:"macaddress"` }{MACAddress: "aa:bb:cc:dd:ee:ff"},
				SetName:   "eth0",
				Addresses: []string{"192.0.2.10/24"},
				Gateway4:  "not-an-ip",
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid gateway4, got nil")
	}
	if !strings.Contains(err.Error(), "invalid gateway4") {
		t.Errorf("error %q should mention invalid gateway4", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_InvalidNameserver(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
			{
				Type:    "nameserver",
				Address: []string{"not-an-ip"},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid nameserver, got nil")
	}
	if !strings.Contains(err.Error(), "invalid nameserver address") {
		t.Errorf("error %q should mention invalid nameserver address", err.Error())
	}
}

func TestGenerateSystemdNetworkConfig_InvalidSearchDomain(t *testing.T) {
	dir := t.TempDir()
	config := types.NetworkConfig{
		Version: 1,
		Config: []types.NetworkConfigV1Entry{
			{
				Type:       "physical",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Subnets:    []types.NetworkConfigV1Subnet{{Type: "dhcp4"}},
			},
			{
				Type:    "nameserver",
				Address: []string{"192.0.2.1"},
				Search:  []string{"invalid domain!"},
			},
		},
	}
	err := generateSystemdNetworkConfigTo(config, dir, filepath.Join(dir, "resolv.conf"))
	if err == nil {
		t.Fatal("expected error for invalid search domain, got nil")
	}
	if !strings.Contains(err.Error(), "invalid search domain") {
		t.Errorf("error %q should mention invalid search domain", err.Error())
	}
}

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"example",
		"my-host.example.org",
		strings.Repeat("a", 63) + ".com",
	}
	for _, d := range valid {
		if !isValidDomain(d) {
			t.Errorf("isValidDomain(%q) = false, want true", d)
		}
	}

	invalid := []string{
		"",
		"invalid domain",
		"domain!",
		"domain\ninjection",
		"-leading.com",
		"trailing-.com",
		"double..dot.com",
		strings.Repeat("a", 254),
		strings.Repeat("a", 64) + ".com",
	}
	for _, d := range invalid {
		if isValidDomain(d) {
			t.Errorf("isValidDomain(%q) = true, want false", d)
		}
	}
}

func TestIsValidIPAddress(t *testing.T) {
	valid := []string{"192.0.2.1", "10.0.0.1", "::1", "2001:db8::1"}
	for _, ip := range valid {
		if !isValidIPAddress(ip) {
			t.Errorf("isValidIPAddress(%q) = false, want true", ip)
		}
	}
	invalid := []string{"", "not-an-ip", "256.0.0.1", "192.0.2", "example.com"}
	for _, ip := range invalid {
		if isValidIPAddress(ip) {
			t.Errorf("isValidIPAddress(%q) = true, want false", ip)
		}
	}
}

func assertFileContains(t *testing.T, path, substr string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if !strings.Contains(string(b), substr) {
		t.Errorf("%s: expected to contain %q\ngot:\n%s", filepath.Base(path), substr, string(b))
	}
}

func assertFileNotContains(t *testing.T, path, substr string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if strings.Contains(string(b), substr) {
		t.Errorf("%s: expected NOT to contain %q\ngot:\n%s", filepath.Base(path), substr, string(b))
	}
}
