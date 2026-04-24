package network

import (
	"fmt"
	"log"
	"net"
	"os"
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

const systemdNetworkDir = "/etc/systemd/network"
const resolvConfPath = "/etc/resolv.conf"

const networkConfigTemplate = `[Match]
MACAddress={{.MacAddress}}

[Network]
{{- if .DHCP }}
DHCP=yes
{{- else }}
Address={{.Address}}/{{.CIDR}}
Gateway={{.Gateway}}
{{- end }}
`

const linkConfigTemplate = `[Match]
MACAddress={{.MacAddress}}

[Link]
Name={{.Name}}
`

const resolvConfTemplate = `search {{.SearchDomain}}
{{range .Nameservers}}nameserver {{.}}
{{end}}options edns0 trust-ad
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

	resolvFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", path, err)
	}
	defer resolvFile.Close()

	if err := resolvTmpl.Execute(resolvFile, resolvData); err != nil {
		return fmt.Errorf("failed to execute resolv.conf template: %v", err)
	}
	log.Printf("Updated %s with DNS configuration", path)
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
			nameservers = entry.Address
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

		subnet := entry.Subnets[0]
		useDHCP := subnet.Type == "dhcp4"

		var cidr int
		if !useDHCP {
			cidr, err = netmaskToCIDR(subnet.Netmask)
			if err != nil {
				return fmt.Errorf("failed to convert netmask to CIDR for %s: %v", entry.Name, err)
			}
		}

		networkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.network", networkDir, entry.Name)
		networkFile, err := os.Create(networkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create network config file for %s: %v", entry.Name, err)
		}
		defer networkFile.Close()

		linkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.link", networkDir, entry.Name)
		linkFile, err := os.Create(linkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create link config file for %s: %v", entry.Name, err)
		}
		defer linkFile.Close()

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
			return fmt.Errorf("failed to execute network template for %s: %v", entry.Name, err)
		}
		log.Printf("Generated systemd-networkd config for interface %s at %s", entry.Name, networkFilePath)

		if err := linkTmpl.Execute(linkFile, linkData); err != nil {
			return fmt.Errorf("failed to execute link template for %s: %v", entry.Name, err)
		}
		log.Printf("Generated systemd-networkd link config for interface %s at %s", entry.Name, linkFilePath)
	}

	if err := updateResolvConfAt(resolvPath, nameservers, searchDomain); err != nil {
		return fmt.Errorf("failed to update resolv.conf: %v", err)
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

		var address string
		var cidr int
		if !eth.DHCP4 {
			if len(eth.Addresses) == 0 {
				return fmt.Errorf("interface %s: no addresses and dhcp4 not set", ifaceName)
			}
			address, cidr, err = parseCIDRAddress(eth.Addresses[0])
			if err != nil {
				return fmt.Errorf("interface %s: %v", ifaceName, err)
			}
		}

		networkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.network", networkDir, ifaceName)
		networkFile, err := os.Create(networkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create network config file for %s: %v", ifaceName, err)
		}
		defer networkFile.Close()

		linkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.link", networkDir, ifaceName)
		linkFile, err := os.Create(linkFilePath)
		if err != nil {
			return fmt.Errorf("failed to create link config file for %s: %v", ifaceName, err)
		}
		defer linkFile.Close()

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
			return fmt.Errorf("failed to execute network template for %s: %v", ifaceName, err)
		}
		log.Printf("Generated systemd-networkd config for interface %s at %s", ifaceName, networkFilePath)

		if err := linkTmpl.Execute(linkFile, linkData); err != nil {
			return fmt.Errorf("failed to execute link template for %s: %v", ifaceName, err)
		}
		log.Printf("Generated systemd-networkd link config for interface %s at %s", ifaceName, linkFilePath)

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
