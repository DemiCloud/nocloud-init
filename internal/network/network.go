package network

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/demicloud/nocloud-init/internal/types"
)

// ifaceNameRe matches valid Linux interface names. Only alphanumerics, colons,
// underscores, and hyphens are permitted to prevent path traversal when
// interpolating names into /etc/systemd/network/ file paths.
var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9:_-]+$`)

func isValidInterfaceName(name string) bool {
	return ifaceNameRe.MatchString(name)
}

// isValidMACAddress returns true if mac is a non-empty string that net.ParseMAC
// can parse.  An empty string is treated as "no MAC specified" and skips
// validation — the caller is responsible for deciding whether that is allowed.
func isValidMACAddress(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

const systemdNetworkDir = "/etc/systemd/network"
const resolvConfPath = "/etc/resolv.conf"

const networkConfigTemplate = `[Match]
MACAddress={{.MacAddress}}

[Network]
{{- if .DHCP }}
DHCP=yes
{{- else }}
Address={{.Address}}/{{.CIDR}}
{{- if .Gateway }}
Gateway={{.Gateway}}
{{- end }}
{{- end }}
`

const linkConfigTemplate = `[Match]
MACAddress={{.MacAddress}}

[Link]
Name={{.Name}}
`

const resolvConfTemplate = `{{- if .SearchDomain}}search {{.SearchDomain}}
{{end -}}{{range .Nameservers}}nameserver {{.}}
{{end}}options edns0
`

func netmaskToCIDR(netmask string) (int, error) {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0, fmt.Errorf("invalid netmask: %s", netmask)
	}
	ones, bits := net.IPMask(ip.To4()).Size()
	if ones == 0 && bits == 0 {
		return 0, fmt.Errorf("non-contiguous netmask: %s", netmask)
	}
	return ones, nil
}

// parseCIDRAddress parses an address in either CIDR prefix notation
// ("192.168.1.10/24") or IP/netmask notation ("192.168.1.10/255.255.255.0").
// Returns the host IP string and prefix length.
func parseCIDRAddress(addr string) (string, int, error) {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err == nil {
		ones, _ := ipNet.Mask.Size()
		return ip.String(), ones, nil
	}
	// Fall back to IP/netmask notation
	parts := strings.SplitN(addr, "/", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	cidr, err := netmaskToCIDR(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	return parts[0], cidr, nil
}

func UpdateResolvConf(nameservers []string, searchDomain string) error {
	return updateResolvConfAt(resolvConfPath, nameservers, searchDomain)
}

func updateResolvConfAt(path string, nameservers []string, searchDomain string) error {
	if _, err := os.Lstat(path); err == nil {
		if link, err := os.Readlink(path); err == nil {
			return fmt.Errorf("%s is a symlink to %s, cannot edit directly", path, link)
		}
	}

	resolvTmpl, err := template.New("resolvConf").Parse(resolvConfTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse resolv.conf template: %v", err)
	}

	resolvData := struct {
		Nameservers  []string
		SearchDomain string
	}{
		Nameservers:  nameservers,
		SearchDomain: searchDomain,
	}

	// Write to a temp file in the same directory as the target so that the
	// subsequent rename is guaranteed to be on the same filesystem — and
	// therefore atomic.  This prevents a window where readers see a truncated
	// file.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".resolv.conf.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %v", path, err)
	}
	tmpName := tmp.Name()
	// On any failure path the temp file is removed; after a successful rename
	// the path no longer exists so os.Remove is a harmless no-op.
	defer os.Remove(tmpName) //nolint:errcheck

	if err := resolvTmpl.Execute(tmp, resolvData); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to execute resolv.conf template: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp resolv.conf: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp resolv.conf: %v", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", tmpName, path, err)
	}
	slog.Info("updated DNS configuration", "path", path)
	return nil
}

func GenerateSystemdNetworkConfig(config types.NetworkConfig) error {
	return generateSystemdNetworkConfigTo(config, systemdNetworkDir, resolvConfPath)
}

func generateSystemdNetworkConfigTo(config types.NetworkConfig, networkDir, resolvPath string) error {
	switch config.Version {
	case 1:
		return generateV1NetworkConfig(config, networkDir, resolvPath)
	case 2:
		return generateV2NetworkConfig(config, networkDir, resolvPath)
	default:
		return fmt.Errorf("unsupported network-config version: %d", config.Version)
	}
}

func generateV1NetworkConfig(config types.NetworkConfig, networkDir, resolvPath string) error {
	networkTmpl, err := template.New("networkConfig").Parse(networkConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse network template: %v", err)
	}
	linkTmpl, err := template.New("linkConfig").Parse(linkConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse link template: %v", err)
	}

	var nameservers []string
	var searchDomain string
	for _, entry := range config.Config {
		if entry.Type == "nameserver" {
			nameservers = append(nameservers, entry.Address...)
			searchDomain = strings.Join(entry.Search, " ")
		}
	}

	for _, entry := range config.Config {
		if entry.Type != "physical" {
			continue
		}
		if len(entry.Subnets) == 0 {
			continue
		}
		if !isValidInterfaceName(entry.Name) {
			return fmt.Errorf("invalid interface name %q: must match [a-zA-Z0-9:_-]+", entry.Name)
		}
		if entry.MacAddress != "" && !isValidMACAddress(entry.MacAddress) {
			return fmt.Errorf("invalid MAC address %q for interface %s", entry.MacAddress, entry.Name)
		}

		if len(entry.Subnets) > 1 {
			slog.Warn("interface has multiple subnets; only the first will be configured", "interface", entry.Name, "count", len(entry.Subnets))
		}
		subnet := entry.Subnets[0]
		useDHCP := subnet.Type == "dhcp4"

		var cidr int
		if !useDHCP {
			cidr, err = netmaskToCIDR(subnet.Netmask)
			if err != nil {
				return fmt.Errorf("failed to convert netmask to CIDR for %s: %v", entry.Name, err)
			}
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+entry.Name+".network")
		networkFile, err := os.Create(networkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create network config file for %s: %v", entry.Name, err)
		}

		linkFilePath := filepath.Join(networkDir, "10-cloud-init-"+entry.Name+".link")
		linkFile, err := os.Create(linkFilePath)
		if err != nil {
			networkFile.Close()
			return fmt.Errorf("failed to create link config file for %s: %v", entry.Name, err)
		}

		networkData := struct {
			Address    string
			CIDR       int
			MacAddress string
			Name       string
			Gateway    string
			DHCP       bool
		}{
			Address:    subnet.Address,
			CIDR:       cidr,
			MacAddress: entry.MacAddress,
			Name:       entry.Name,
			Gateway:    subnet.Gateway,
			DHCP:       useDHCP,
		}
		linkData := struct {
			MacAddress string
			Name       string
		}{
			MacAddress: entry.MacAddress,
			Name:       entry.Name,
		}

		if err := networkTmpl.Execute(networkFile, networkData); err != nil {
			networkFile.Close()
			linkFile.Close()
			return fmt.Errorf("failed to execute network template for %s: %v", entry.Name, err)
		}
		if err := networkFile.Sync(); err != nil {
			networkFile.Close()
			linkFile.Close()
			return fmt.Errorf("failed to sync network config file for %s: %v", entry.Name, err)
		}
		if err := networkFile.Close(); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to close network config file for %s: %v", entry.Name, err)
		}
		slog.Info("generated network config", "interface", entry.Name, "path", networkFilePath)

		if err := linkTmpl.Execute(linkFile, linkData); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to execute link template for %s: %v", entry.Name, err)
		}
		if err := linkFile.Sync(); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to sync link config file for %s: %v", entry.Name, err)
		}
		if err := linkFile.Close(); err != nil {
			return fmt.Errorf("failed to close link config file for %s: %v", entry.Name, err)
		}
		slog.Info("generated link config", "interface", entry.Name, "path", linkFilePath)
	}

	if len(nameservers) > 0 {
		if err := updateResolvConfAt(resolvPath, nameservers, searchDomain); err != nil {
			return fmt.Errorf("failed to update resolv.conf: %v", err)
		}
	}
	return nil
}

func generateV2NetworkConfig(config types.NetworkConfig, networkDir, resolvPath string) error {
	networkTmpl, err := template.New("networkConfig").Parse(networkConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse network template: %v", err)
	}
	linkTmpl, err := template.New("linkConfig").Parse(linkConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse link template: %v", err)
	}

	var nameservers []string
	var searchDomains []string

	// Sort keys for deterministic output
	names := make([]string, 0, len(config.Ethernets))
	for name := range config.Ethernets {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, key := range names {
		eth := config.Ethernets[key]

		// Use set-name if provided, otherwise use the map key
		ifaceName := eth.SetName
		if ifaceName == "" {
			ifaceName = key
		}

		if !isValidInterfaceName(ifaceName) {
			return fmt.Errorf("invalid interface name %q: must match [a-zA-Z0-9:_-]+", ifaceName)
		}
		if mac := eth.Match.MACAddress; mac != "" && !isValidMACAddress(mac) {
			return fmt.Errorf("invalid MAC address %q for interface %s", mac, ifaceName)
		}

		var address string
		var cidr int
		if !eth.DHCP4 {
			if len(eth.Addresses) == 0 {
				return fmt.Errorf("interface %s: no addresses and dhcp4 not set", ifaceName)
			}
			if len(eth.Addresses) > 1 {
				slog.Warn("interface has multiple addresses; only the first will be configured", "interface", ifaceName, "count", len(eth.Addresses))
			}
			address, cidr, err = parseCIDRAddress(eth.Addresses[0])
			if err != nil {
				return fmt.Errorf("interface %s: %v", ifaceName, err)
			}
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+ifaceName+".network")
		networkFile, err := os.Create(networkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create network config file for %s: %v", ifaceName, err)
		}

		linkFilePath := filepath.Join(networkDir, "10-cloud-init-"+ifaceName+".link")
		linkFile, err := os.Create(linkFilePath)
		if err != nil {
			networkFile.Close()
			return fmt.Errorf("failed to create link config file for %s: %v", ifaceName, err)
		}

		networkData := struct {
			Address    string
			CIDR       int
			MacAddress string
			Name       string
			Gateway    string
			DHCP       bool
		}{
			Address:    address,
			CIDR:       cidr,
			MacAddress: eth.Match.MACAddress,
			Name:       ifaceName,
			Gateway:    eth.Gateway4,
			DHCP:       eth.DHCP4,
		}
		linkData := struct {
			MacAddress string
			Name       string
		}{
			MacAddress: eth.Match.MACAddress,
			Name:       ifaceName,
		}

		if err := networkTmpl.Execute(networkFile, networkData); err != nil {
			networkFile.Close()
			linkFile.Close()
			return fmt.Errorf("failed to execute network template for %s: %v", ifaceName, err)
		}
		if err := networkFile.Sync(); err != nil {
			networkFile.Close()
			linkFile.Close()
			return fmt.Errorf("failed to sync network config file for %s: %v", ifaceName, err)
		}
		if err := networkFile.Close(); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to close network config file for %s: %v", ifaceName, err)
		}
		slog.Info("generated network config", "interface", ifaceName, "path", networkFilePath)

		if err := linkTmpl.Execute(linkFile, linkData); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to execute link template for %s: %v", ifaceName, err)
		}
		if err := linkFile.Sync(); err != nil {
			linkFile.Close()
			return fmt.Errorf("failed to sync link config file for %s: %v", ifaceName, err)
		}
		if err := linkFile.Close(); err != nil {
			return fmt.Errorf("failed to close link config file for %s: %v", ifaceName, err)
		}
		slog.Info("generated link config", "interface", ifaceName, "path", linkFilePath)

		nameservers = append(nameservers, eth.Nameservers.Addresses...)
		searchDomains = append(searchDomains, eth.Nameservers.Search...)
	}

	if len(nameservers) > 0 {
		if err := updateResolvConfAt(resolvPath, nameservers, strings.Join(searchDomains, " ")); err != nil {
			return fmt.Errorf("failed to update resolv.conf: %v", err)
		}
	}
	return nil
}
