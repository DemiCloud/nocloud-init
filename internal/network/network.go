package network

import (
	"bytes"
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

// isValidIPAddress returns true if ip is a valid IPv4 or IPv6 address string.
func isValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// domainLabelRe matches a single valid DNS label: starts and ends with an
// alphanumeric character; interior may include hyphens.
var domainLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// isValidDomain returns true if domain is a syntactically valid DNS name
// (single label or FQDN).  Each label must conform to RFC 1035 §2.3.4.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if !domainLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// deduplicateStrings returns a new slice containing the elements of in with
// duplicates removed, preserving first-seen order.
func deduplicateStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// writeFileBytes atomically writes data to path using a temp-file-then-rename
// strategy so that readers never observe a truncated or partially-written file.
// The temp file is created in the same directory as path to guarantee the
// rename is on the same filesystem.
func writeFileBytes(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cloud-init-net.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// On any failure path the temp file is removed; after a successful rename
	// the path no longer exists so os.Remove is a harmless no-op.
	defer os.Remove(tmpName) //nolint:errcheck

	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod temp file for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp file for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// writeNetworkFile renders tmpl with data and atomically writes the result to
// path using a temp-file-then-rename strategy so that readers never observe a
// truncated or partially-written file.  The temp file is created in the same
// directory as path to guarantee the rename is on the same filesystem.
func writeNetworkFile(path string, tmpl *template.Template, data interface{}) error {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template for %s: %w", path, err)
	}
	return writeFileBytes(path, buf.Bytes())
}

const systemdNetworkDir = "/etc/systemd/network"
const resolvConfPath = "/etc/resolv.conf"

const networkConfigTemplate = `[Match]
{{- if .MacAddress}}
MACAddress={{.MacAddress}}
{{- else}}
Name={{.Name}}
{{- end}}

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
	if net.ParseIP(parts[0]) == nil {
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

	var buf bytes.Buffer
	if err := resolvTmpl.Execute(&buf, resolvData); err != nil {
		return fmt.Errorf("failed to execute resolv.conf template: %w", err)
	}
	if err := writeFileBytes(path, buf.Bytes()); err != nil {
		return err
	}
	slog.Info("updated DNS configuration", "path", path)
	return nil
}

func GenerateSystemdNetworkConfig(config types.NetworkConfig) error {
	return generateSystemdNetworkConfigTo(config, systemdNetworkDir, resolvConfPath)
}

// cleanStaleCIDataFiles removes all previously-written `10-cloud-init-*` files
// from networkDir.  This is called at the start of every run so that NICs
// removed or renamed in the hypervisor UI are not left behind in
// /etc/systemd/network — which would cause systemd-networkd to attempt to
// configure hardware that no longer exists.
func cleanStaleCIDataFiles(networkDir string) error {
	matches, err := filepath.Glob(filepath.Join(networkDir, "10-cloud-init-*"))
	if err != nil {
		return fmt.Errorf("failed to glob stale cloud-init files in %s: %w", networkDir, err)
	}
	for _, path := range matches {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove stale cloud-init file %s: %w", path, err)
		}
		slog.Debug("removed stale cloud-init network file", "path", path)
	}
	return nil
}

func generateSystemdNetworkConfigTo(config types.NetworkConfig, networkDir, resolvPath string) error {
	if err := cleanStaleCIDataFiles(networkDir); err != nil {
		return err
	}
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
	var searchDomains []string
	for _, entry := range config.Config {
		if entry.Type == "nameserver" {
			nameservers = append(nameservers, entry.Address...)
			searchDomains = append(searchDomains, entry.Search...)
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
			if !isValidIPAddress(subnet.Address) {
				return fmt.Errorf("interface %s: invalid address %q", entry.Name, subnet.Address)
			}
			if subnet.Gateway != "" && !isValidIPAddress(subnet.Gateway) {
				return fmt.Errorf("interface %s: invalid gateway %q", entry.Name, subnet.Gateway)
			}
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+entry.Name+".network")
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
		if err := writeNetworkFile(networkFilePath, networkTmpl, networkData); err != nil {
			return fmt.Errorf("failed to write network config for %s: %v", entry.Name, err)
		}
		slog.Info("generated network config", "interface", entry.Name, "path", networkFilePath)

		if entry.MacAddress != "" {
			linkFilePath := filepath.Join(networkDir, "10-cloud-init-"+entry.Name+".link")
			linkData := struct {
				MacAddress string
				Name       string
			}{
				MacAddress: entry.MacAddress,
				Name:       entry.Name,
			}
			if err := writeNetworkFile(linkFilePath, linkTmpl, linkData); err != nil {
				return fmt.Errorf("failed to write link config for %s: %v", entry.Name, err)
			}
			slog.Info("generated link config", "interface", entry.Name, "path", linkFilePath)
		} else {
			slog.Warn("interface has no MAC address; skipping link file", "interface", entry.Name)
		}
	}

	if len(nameservers) > 0 {
		for _, ns := range nameservers {
			if !isValidIPAddress(ns) {
				return fmt.Errorf("invalid nameserver address %q", ns)
			}
		}
		for _, sd := range searchDomains {
			if !isValidDomain(sd) {
				return fmt.Errorf("invalid search domain %q", sd)
			}
		}
		if err := updateResolvConfAt(resolvPath, deduplicateStrings(nameservers), strings.Join(deduplicateStrings(searchDomains), " ")); err != nil {
			return fmt.Errorf("failed to update resolv.conf: %w", err)
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

		if eth.Gateway4 != "" && !isValidIPAddress(eth.Gateway4) {
			return fmt.Errorf("interface %s: invalid gateway4 %q", ifaceName, eth.Gateway4)
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+ifaceName+".network")
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
		if err := writeNetworkFile(networkFilePath, networkTmpl, networkData); err != nil {
			return fmt.Errorf("failed to write network config for %s: %v", ifaceName, err)
		}
		slog.Info("generated network config", "interface", ifaceName, "path", networkFilePath)

		if eth.Match.MACAddress != "" {
			linkFilePath := filepath.Join(networkDir, "10-cloud-init-"+ifaceName+".link")
			linkData := struct {
				MacAddress string
				Name       string
			}{
				MacAddress: eth.Match.MACAddress,
				Name:       ifaceName,
			}
			if err := writeNetworkFile(linkFilePath, linkTmpl, linkData); err != nil {
				return fmt.Errorf("failed to write link config for %s: %v", ifaceName, err)
			}
			slog.Info("generated link config", "interface", ifaceName, "path", linkFilePath)
		} else {
			slog.Warn("interface has no MAC address; skipping link file", "interface", ifaceName)
		}

		nameservers = append(nameservers, eth.Nameservers.Addresses...)
		searchDomains = append(searchDomains, eth.Nameservers.Search...)
	}

	if len(nameservers) > 0 {
		for _, ns := range nameservers {
			if !isValidIPAddress(ns) {
				return fmt.Errorf("invalid nameserver address %q", ns)
			}
		}
		for _, sd := range searchDomains {
			if !isValidDomain(sd) {
				return fmt.Errorf("invalid search domain %q", sd)
			}
		}
		if err := updateResolvConfAt(resolvPath, deduplicateStrings(nameservers), strings.Join(deduplicateStrings(searchDomains), " ")); err != nil {
			return fmt.Errorf("failed to update resolv.conf: %w", err)
		}
	}
	return nil
}
