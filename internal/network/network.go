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

// isValidRouteDestination returns true if dst is a valid route destination:
// either empty/unset (treated as a default route), the literal "default", or
// a CIDR prefix (e.g. "192.168.1.0/24", "0.0.0.0/0").
func isValidRouteDestination(dst string) bool {
	if dst == "" || dst == "default" {
		return true
	}
	_, _, err := net.ParseCIDR(dst)
	return err == nil
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
{{- if and .DHCP4 .DHCP6}}
DHCP=yes
{{- else if .DHCP4}}
DHCP=ipv4
{{- else if .DHCP6}}
DHCP=ipv6
{{- else}}
{{- range .Addresses}}
Address={{.}}
{{- end}}
{{- if .Gateway}}
Gateway={{.Gateway}}
{{- end}}
{{- end}}
{{- if .Optional}}
RequiredForOnline=no
{{- end}}
{{- range .VLANs}}
VLAN={{.}}
{{- end}}
{{- if .Gateway6}}

[Route]
Gateway={{.Gateway6}}
{{- end}}
{{- range .Routes}}

[Route]
{{- if and .To (ne .To "default")}}
Destination={{.To}}
{{- end}}
Gateway={{.Via}}
{{- end}}
{{- if .MTU}}

[Link]
MTUBytes={{.MTU}}
{{- end}}
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

const netdevVLANTemplate = `[NetDev]
Name={{.Name}}
Kind=vlan

[VLAN]
Id={{.ID}}
`

const networkVLANMemberTemplate = `VLAN={{.VLANName}}
`

const netdevBondTemplate = `[NetDev]
Name={{.Name}}
Kind=bond
{{- if .Mode}}

[Bond]
Mode={{.Mode}}
{{- end}}
{{- if .LACPRate}}
LACPTransmitRate={{.LACPRate}}
{{- end}}
{{- if .MIIMonitorInterval}}
MIIMonitorSec={{.MIIMonitorInterval}}
{{- end}}
{{- if .MinLinks}}
MinLinks={{.MinLinks}}
{{- end}}
{{- if .TransmitHashPolicy}}
TransmitHashPolicy={{.TransmitHashPolicy}}
{{- end}}
{{- if .ARPInterval}}
ARPIntervalSec={{.ARPInterval}}
{{- end}}
{{- if .UpDelay}}
UpDelaySec={{.UpDelay}}
{{- end}}
{{- if .DownDelay}}
DownDelaySec={{.DownDelay}}
{{- end}}
`

const networkBondMemberTemplate = `[Match]
Name={{.MemberName}}

[Network]
Bond={{.BondName}}
`

const netdevBridgeTemplate = `[NetDev]
Name={{.Name}}
Kind=bridge
{{- if or .STP .ForwardDelay .HelloTime .MaxAge .AgeingTime .Priority}}

[Bridge]
{{- if .STP}}
STP={{.STP}}
{{- end}}
{{- if .ForwardDelay}}
ForwardDelaySec={{.ForwardDelay}}
{{- end}}
{{- if .HelloTime}}
HelloTimeSec={{.HelloTime}}
{{- end}}
{{- if .MaxAge}}
MaxAgeSec={{.MaxAge}}
{{- end}}
{{- if .AgeingTime}}
AgeingTimeSec={{.AgeingTime}}
{{- end}}
{{- if .Priority}}
Priority={{.Priority}}
{{- end}}
{{- end}}
`

const networkBridgeMemberTemplate = `[Match]
Name={{.MemberName}}

[Network]
Bridge={{.BridgeName}}
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
	parsedIP := net.ParseIP(parts[0])
	if parsedIP == nil {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	cidr, err := netmaskToCIDR(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}
	return parsedIP.String(), cidr, nil
}

func UpdateResolvConf(nameservers []string, searchDomain string) error {
	return updateResolvConfAt(resolvConfPath, nameservers, searchDomain)
}

func updateResolvConfAt(path string, nameservers []string, searchDomain string) error {
	if _, err := os.Lstat(path); err == nil {
		if link, err := os.Readlink(path); err == nil {
			// resolv.conf is owned by a stub resolver (e.g. systemd-resolved,
			// dnsmasq, unbound). On networkd systems the DNS= lines in .network
			// files are passed to the resolver automatically, so no direct write
			// is needed. Skip silently rather than treating this as an error.
			slog.Info("resolv.conf is a symlink, skipping direct write; DNS will be applied via .network files",
				"path", path, "target", link)
			return nil
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

		var useDHCP4, useDHCP6 bool
		for _, subnet := range entry.Subnets {
			switch subnet.Type {
			case "dhcp4":
				useDHCP4 = true
			case "dhcp6":
				useDHCP6 = true
			}
		}

		var addresses []string
		var gateway string
		if !useDHCP4 && !useDHCP6 {
			for _, subnet := range entry.Subnets {
				cidr, err := netmaskToCIDR(subnet.Netmask)
				if err != nil {
					return fmt.Errorf("failed to convert netmask to CIDR for %s: %v", entry.Name, err)
				}
				if !isValidIPAddress(subnet.Address) {
					return fmt.Errorf("interface %s: invalid address %q", entry.Name, subnet.Address)
				}
				if subnet.Gateway != "" && !isValidIPAddress(subnet.Gateway) {
					return fmt.Errorf("interface %s: invalid gateway %q", entry.Name, subnet.Gateway)
				}
				addresses = append(addresses, fmt.Sprintf("%s/%d", subnet.Address, cidr))
				if gateway == "" && subnet.Gateway != "" {
					gateway = subnet.Gateway
				}
				// Per-subnet DNS overrides the global nameserver entries.
				nameservers = append(nameservers, subnet.DNSNameservers...)
				searchDomains = append(searchDomains, subnet.DNSSearch...)
			}
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+entry.Name+".network")
		networkData := struct {
			Addresses  []string
			MacAddress string
			Name       string
			Gateway    string
			Gateway6   string
			DHCP4      bool
			DHCP6      bool
			Optional   bool
			MTU        int
			VLANs      []string
			Routes     []types.NetworkConfigV2Route
		}{
			Addresses:  addresses,
			MacAddress: entry.MacAddress,
			Name:       entry.Name,
			Gateway:    gateway,
			DHCP4:      useDHCP4,
			DHCP6:      useDHCP6,
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
	netdevVLANTmpl, err := template.New("netdevVLAN").Parse(netdevVLANTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse netdev VLAN template: %v", err)
	}
	netdevBondTmpl, err := template.New("netdevBond").Parse(netdevBondTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse netdev bond template: %v", err)
	}
	bondMemberTmpl, err := template.New("bondMember").Parse(networkBondMemberTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse bond member template: %v", err)
	}
	netdevBridgeTmpl, err := template.New("netdevBridge").Parse(netdevBridgeTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse netdev bridge template: %v", err)
	}
	bridgeMemberTmpl, err := template.New("bridgeMember").Parse(networkBridgeMemberTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse bridge member template: %v", err)
	}

	var nameservers []string
	var searchDomains []string

	// Build a map from ethernet key → sorted list of VLAN device names attached
	// to that parent, so we can append VLAN= lines to the parent .network file.
	parentToVLANs := make(map[string][]string)
	if len(config.VLANs) > 0 {
		vlanNames := make([]string, 0, len(config.VLANs))
		for name := range config.VLANs {
			vlanNames = append(vlanNames, name)
		}
		sort.Strings(vlanNames)
		for _, vlanName := range vlanNames {
			v := config.VLANs[vlanName]
			if v.Link == "" {
				return fmt.Errorf("vlan %q: link must be set to a parent ethernet ID", vlanName)
			}
			parentToVLANs[v.Link] = append(parentToVLANs[v.Link], vlanName)
		}
	}

	// Sort keys for deterministic output
	names := make([]string, 0, len(config.Ethernets))
	for name := range config.Ethernets {
		names = append(names, name)
	}
	sort.Strings(names)

	// Build set of ethernet keys that are bond/bridge members so we can skip
	// them in the ethernet loop.
	bondMembers := make(map[string]bool)
	for _, b := range config.Bonds {
		for _, member := range b.Interfaces {
			bondMembers[member] = true
		}
	}
	for _, br := range config.Bridges {
		for _, member := range br.Interfaces {
			bondMembers[member] = true
		}
	}

	for _, key := range names {
		if bondMembers[key] {
			continue
		}
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

		var addresses []string
		if !eth.DHCP4 && !eth.DHCP6 {
			if len(eth.Addresses) == 0 && len(parentToVLANs[key]) == 0 {
				return fmt.Errorf("interface %s: no addresses and dhcp4/dhcp6 not set", ifaceName)
			}
			for _, addr := range eth.Addresses {
				ip, prefix, parseErr := parseCIDRAddress(addr)
				if parseErr != nil {
					return fmt.Errorf("interface %s: %v", ifaceName, parseErr)
				}
				addresses = append(addresses, fmt.Sprintf("%s/%d", ip, prefix))
			}
		}

		if eth.Gateway4 != "" && !isValidIPAddress(eth.Gateway4) {
			return fmt.Errorf("interface %s: invalid gateway4 %q", ifaceName, eth.Gateway4)
		}
		if eth.Gateway6 != "" && !isValidIPAddress(eth.Gateway6) {
			return fmt.Errorf("interface %s: invalid gateway6 %q", ifaceName, eth.Gateway6)
		}
		for _, r := range eth.Routes {
			if !isValidRouteDestination(r.To) {
				return fmt.Errorf("interface %s: route: invalid destination %q", ifaceName, r.To)
			}
			if !isValidIPAddress(r.Via) {
				return fmt.Errorf("interface %s: route to %q: invalid gateway %q", ifaceName, r.To, r.Via)
			}
		}

		networkFilePath := filepath.Join(networkDir, "10-cloud-init-"+ifaceName+".network")
		networkData := struct {
			Addresses  []string
			MacAddress string
			Name       string
			Gateway    string
			Gateway6   string
			DHCP4      bool
			DHCP6      bool
			Optional   bool
			MTU        int
			VLANs      []string
			Routes     []types.NetworkConfigV2Route
		}{
			Addresses:  addresses,
			MacAddress: eth.Match.MACAddress,
			Name:       ifaceName,
			Gateway:    eth.Gateway4,
			Gateway6:   eth.Gateway6,
			DHCP4:      eth.DHCP4,
			DHCP6:      eth.DHCP6,
			Optional:   eth.Optional,
			MTU:        eth.MTU,
			VLANs:      parentToVLANs[key],
			Routes:     eth.Routes,
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

	// Generate .netdev and .network files for each VLAN.
	if len(config.VLANs) > 0 {
		vlanNames := make([]string, 0, len(config.VLANs))
		for name := range config.VLANs {
			vlanNames = append(vlanNames, name)
		}
		sort.Strings(vlanNames)

		for _, vlanName := range vlanNames {
			v := config.VLANs[vlanName]
			if !isValidInterfaceName(vlanName) {
				return fmt.Errorf("invalid VLAN interface name %q", vlanName)
			}
			if v.ID < 0 || v.ID > 4094 {
				return fmt.Errorf("vlan %q: id %d is out of range (0–4094)", vlanName, v.ID)
			}

			// .netdev file
			netdevPath := filepath.Join(networkDir, "10-cloud-init-"+vlanName+".netdev")
			netdevData := struct {
				Name string
				ID   int
			}{Name: vlanName, ID: v.ID}
			if err := writeNetworkFile(netdevPath, netdevVLANTmpl, netdevData); err != nil {
				return fmt.Errorf("failed to write netdev for VLAN %s: %v", vlanName, err)
			}
			slog.Info("generated VLAN netdev", "vlan", vlanName, "path", netdevPath)

			// .network file for the VLAN interface itself
			var vlanAddresses []string
			if !v.DHCP4 && !v.DHCP6 {
				for _, addr := range v.Addresses {
					ip, prefix, parseErr := parseCIDRAddress(addr)
					if parseErr != nil {
						return fmt.Errorf("vlan %s: %v", vlanName, parseErr)
					}
					vlanAddresses = append(vlanAddresses, fmt.Sprintf("%s/%d", ip, prefix))
				}
			}
			if v.Gateway4 != "" && !isValidIPAddress(v.Gateway4) {
				return fmt.Errorf("vlan %s: invalid gateway4 %q", vlanName, v.Gateway4)
			}
			if v.Gateway6 != "" && !isValidIPAddress(v.Gateway6) {
				return fmt.Errorf("vlan %s: invalid gateway6 %q", vlanName, v.Gateway6)
			}
			for _, r := range v.Routes {
				if !isValidRouteDestination(r.To) {
					return fmt.Errorf("vlan %s: route: invalid destination %q", vlanName, r.To)
				}
				if !isValidIPAddress(r.Via) {
					return fmt.Errorf("vlan %s: route to %q: invalid gateway %q", vlanName, r.To, r.Via)
				}
			}

			vlanNetworkPath := filepath.Join(networkDir, "10-cloud-init-"+vlanName+".network")
			vlanNetworkData := struct {
				Addresses  []string
				MacAddress string
				Name       string
				Gateway    string
				Gateway6   string
				DHCP4      bool
				DHCP6      bool
				Optional   bool
				MTU        int
				VLANs      []string
				Routes     []types.NetworkConfigV2Route
			}{
				Addresses: vlanAddresses,
				Name:      vlanName,
				Gateway:   v.Gateway4,
				Gateway6:  v.Gateway6,
				DHCP4:     v.DHCP4,
				DHCP6:     v.DHCP6,
				Optional:  v.Optional,
				MTU:       v.MTU,
				Routes:    v.Routes,
			}
			if err := writeNetworkFile(vlanNetworkPath, networkTmpl, vlanNetworkData); err != nil {
				return fmt.Errorf("failed to write network config for VLAN %s: %v", vlanName, err)
			}
			slog.Info("generated VLAN network config", "vlan", vlanName, "path", vlanNetworkPath)

			nameservers = append(nameservers, v.Nameservers.Addresses...)
			searchDomains = append(searchDomains, v.Nameservers.Search...)
		}
	}

	// Generate .netdev and .network files for each bond.
	if len(config.Bonds) > 0 {
		bondNames := make([]string, 0, len(config.Bonds))
		for name := range config.Bonds {
			bondNames = append(bondNames, name)
		}
		sort.Strings(bondNames)

		for _, bondName := range bondNames {
			b := config.Bonds[bondName]
			if !isValidInterfaceName(bondName) {
				return fmt.Errorf("invalid bond interface name %q", bondName)
			}
			if len(b.Interfaces) == 0 {
				return fmt.Errorf("bond %q: interfaces list must not be empty", bondName)
			}

			// .netdev file
			netdevPath := filepath.Join(networkDir, "10-cloud-init-"+bondName+".netdev")
			netdevData := struct {
				Name               string
				Mode               string
				LACPRate           string
				MIIMonitorInterval string
				MinLinks           int
				TransmitHashPolicy string
				ARPInterval        string
				UpDelay            string
				DownDelay          string
			}{
				Name:               bondName,
				Mode:               b.Parameters.Mode,
				LACPRate:           b.Parameters.LACPRate,
				MIIMonitorInterval: b.Parameters.MIIMonitorInterval,
				MinLinks:           b.Parameters.MinLinks,
				TransmitHashPolicy: b.Parameters.TransmitHashPolicy,
				ARPInterval:        b.Parameters.ARPInterval,
				UpDelay:            b.Parameters.UpDelay,
				DownDelay:          b.Parameters.DownDelay,
			}
			if err := writeNetworkFile(netdevPath, netdevBondTmpl, netdevData); err != nil {
				return fmt.Errorf("failed to write netdev for bond %s: %v", bondName, err)
			}
			slog.Info("generated bond netdev", "bond", bondName, "path", netdevPath)

			// .network file for the bond interface itself
			var bondAddresses []string
			if !b.DHCP4 && !b.DHCP6 {
				for _, addr := range b.Addresses {
					ip, prefix, parseErr := parseCIDRAddress(addr)
					if parseErr != nil {
						return fmt.Errorf("bond %s: %v", bondName, parseErr)
					}
					bondAddresses = append(bondAddresses, fmt.Sprintf("%s/%d", ip, prefix))
				}
			}
			if b.Gateway4 != "" && !isValidIPAddress(b.Gateway4) {
				return fmt.Errorf("bond %s: invalid gateway4 %q", bondName, b.Gateway4)
			}
			if b.Gateway6 != "" && !isValidIPAddress(b.Gateway6) {
				return fmt.Errorf("bond %s: invalid gateway6 %q", bondName, b.Gateway6)
			}
			for _, r := range b.Routes {
				if !isValidRouteDestination(r.To) {
					return fmt.Errorf("bond %s: route: invalid destination %q", bondName, r.To)
				}
				if !isValidIPAddress(r.Via) {
					return fmt.Errorf("bond %s: route to %q: invalid gateway %q", bondName, r.To, r.Via)
				}
			}

			bondNetworkPath := filepath.Join(networkDir, "10-cloud-init-"+bondName+".network")
			bondNetworkData := struct {
				Addresses  []string
				MacAddress string
				Name       string
				Gateway    string
				Gateway6   string
				DHCP4      bool
				DHCP6      bool
				Optional   bool
				MTU        int
				VLANs      []string
				Routes     []types.NetworkConfigV2Route
			}{
				Addresses: bondAddresses,
				Name:      bondName,
				Gateway:   b.Gateway4,
				Gateway6:  b.Gateway6,
				DHCP4:     b.DHCP4,
				DHCP6:     b.DHCP6,
				Optional:  b.Optional,
				MTU:       b.MTU,
				Routes:    b.Routes,
			}
			if err := writeNetworkFile(bondNetworkPath, networkTmpl, bondNetworkData); err != nil {
				return fmt.Errorf("failed to write network config for bond %s: %v", bondName, err)
			}
			slog.Info("generated bond network config", "bond", bondName, "path", bondNetworkPath)

			// .network file for each bond member interface
			for _, memberKey := range b.Interfaces {
				if !isValidInterfaceName(memberKey) {
					return fmt.Errorf("bond %q: invalid member interface name %q", bondName, memberKey)
				}
				// Resolve the actual interface name (set-name or key)
				memberName := memberKey
				if eth, ok := config.Ethernets[memberKey]; ok && eth.SetName != "" {
					memberName = eth.SetName
				}
				memberPath := filepath.Join(networkDir, "10-cloud-init-"+memberName+"-bond.network")
				memberData := struct {
					MemberName string
					BondName   string
				}{MemberName: memberName, BondName: bondName}
				if err := writeNetworkFile(memberPath, bondMemberTmpl, memberData); err != nil {
					return fmt.Errorf("bond %s: failed to write member network config for %s: %v", bondName, memberName, err)
				}
				slog.Info("generated bond member network config", "member", memberName, "bond", bondName, "path", memberPath)
			}

			nameservers = append(nameservers, b.Nameservers.Addresses...)
			searchDomains = append(searchDomains, b.Nameservers.Search...)
		}
	}

	// Generate .netdev and .network files for each bridge.
	if len(config.Bridges) > 0 {
		bridgeNames := make([]string, 0, len(config.Bridges))
		for name := range config.Bridges {
			bridgeNames = append(bridgeNames, name)
		}
		sort.Strings(bridgeNames)

		for _, bridgeName := range bridgeNames {
			br := config.Bridges[bridgeName]
			if !isValidInterfaceName(bridgeName) {
				return fmt.Errorf("invalid bridge interface name %q", bridgeName)
			}
			if len(br.Interfaces) == 0 {
				return fmt.Errorf("bridge %q: interfaces list must not be empty", bridgeName)
			}

			// Convert *bool STP parameter to "yes"/"no"/"" for the template.
			stpStr := ""
			if br.Parameters.STP != nil {
				if *br.Parameters.STP {
					stpStr = "yes"
				} else {
					stpStr = "no"
				}
			}

			// .netdev file
			netdevPath := filepath.Join(networkDir, "10-cloud-init-"+bridgeName+".netdev")
			netdevData := struct {
				Name         string
				STP          string
				ForwardDelay int
				HelloTime    int
				MaxAge       int
				AgeingTime   int
				Priority     int
			}{
				Name:         bridgeName,
				STP:          stpStr,
				ForwardDelay: br.Parameters.ForwardDelay,
				HelloTime:    br.Parameters.HelloTime,
				MaxAge:       br.Parameters.MaxAge,
				AgeingTime:   br.Parameters.AgeingTime,
				Priority:     br.Parameters.Priority,
			}
			if err := writeNetworkFile(netdevPath, netdevBridgeTmpl, netdevData); err != nil {
				return fmt.Errorf("failed to write netdev for bridge %s: %v", bridgeName, err)
			}
			slog.Info("generated bridge netdev", "bridge", bridgeName, "path", netdevPath)

			// .network file for the bridge interface itself
			var bridgeAddresses []string
			if !br.DHCP4 && !br.DHCP6 {
				for _, addr := range br.Addresses {
					ip, prefix, parseErr := parseCIDRAddress(addr)
					if parseErr != nil {
						return fmt.Errorf("bridge %s: %v", bridgeName, parseErr)
					}
					bridgeAddresses = append(bridgeAddresses, fmt.Sprintf("%s/%d", ip, prefix))
				}
			}
			if br.Gateway4 != "" && !isValidIPAddress(br.Gateway4) {
				return fmt.Errorf("bridge %s: invalid gateway4 %q", bridgeName, br.Gateway4)
			}
			if br.Gateway6 != "" && !isValidIPAddress(br.Gateway6) {
				return fmt.Errorf("bridge %s: invalid gateway6 %q", bridgeName, br.Gateway6)
			}
			for _, r := range br.Routes {
				if !isValidRouteDestination(r.To) {
					return fmt.Errorf("bridge %s: route: invalid destination %q", bridgeName, r.To)
				}
				if !isValidIPAddress(r.Via) {
					return fmt.Errorf("bridge %s: route to %q: invalid gateway %q", bridgeName, r.To, r.Via)
				}
			}

			bridgeNetworkPath := filepath.Join(networkDir, "10-cloud-init-"+bridgeName+".network")
			bridgeNetworkData := struct {
				Addresses  []string
				MacAddress string
				Name       string
				Gateway    string
				Gateway6   string
				DHCP4      bool
				DHCP6      bool
				Optional   bool
				MTU        int
				VLANs      []string
				Routes     []types.NetworkConfigV2Route
			}{
				Addresses: bridgeAddresses,
				Name:      bridgeName,
				Gateway:   br.Gateway4,
				Gateway6:  br.Gateway6,
				DHCP4:     br.DHCP4,
				DHCP6:     br.DHCP6,
				Optional:  br.Optional,
				MTU:       br.MTU,
				Routes:    br.Routes,
			}
			if err := writeNetworkFile(bridgeNetworkPath, networkTmpl, bridgeNetworkData); err != nil {
				return fmt.Errorf("failed to write network config for bridge %s: %v", bridgeName, err)
			}
			slog.Info("generated bridge network config", "bridge", bridgeName, "path", bridgeNetworkPath)

			// .network file for each bridge member interface
			for _, memberKey := range br.Interfaces {
				if !isValidInterfaceName(memberKey) {
					return fmt.Errorf("bridge %q: invalid member interface name %q", bridgeName, memberKey)
				}
				// Resolve the actual interface name (set-name or key)
				memberName := memberKey
				if eth, ok := config.Ethernets[memberKey]; ok && eth.SetName != "" {
					memberName = eth.SetName
				}
				memberPath := filepath.Join(networkDir, "10-cloud-init-"+memberName+"-bridge.network")
				memberData := struct {
					MemberName string
					BridgeName string
				}{MemberName: memberName, BridgeName: bridgeName}
				if err := writeNetworkFile(memberPath, bridgeMemberTmpl, memberData); err != nil {
					return fmt.Errorf("bridge %s: failed to write member network config for %s: %v", bridgeName, memberName, err)
				}
				slog.Info("generated bridge member network config", "member", memberName, "bridge", bridgeName, "path", memberPath)
			}

			nameservers = append(nameservers, br.Nameservers.Addresses...)
			searchDomains = append(searchDomains, br.Nameservers.Search...)
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
