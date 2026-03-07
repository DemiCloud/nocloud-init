package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/godbus/dbus/v5"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

const (
	__VERSION__        = "0.17.0"
	serviceName        = "nocloud-init"
	serviceDescription = "A Cloud-init client for NoCloud"

	// Path Constants
	systemdNetworkDir = "/etc/systemd/network"
	systemdServiceDir = "/etc/systemd/system"
	sshKeyPath        = "/etc/ssh/ssh_host_rsa_key"
	resolvConfPath    = "/etc/resolv.conf"

	cidataLabelPath = "/dev/disk/by-label/CIDATA"
)

var requiredPrograms = []string{
	"networkctl",
	"usermod",
	"hostnamectl",
	"ssh-keygen",
}

var requiredDirectories = []string{
	systemdNetworkDir,
}

type UserData struct {
	Hostname       string `yaml:"hostname" json:"hostname"`
	ManageEtcHosts bool   `yaml:"manage_etc_hosts" json:"manage_etc_hosts"`
	FQDN           string `yaml:"fqdn" json:"fqdn"`
	User           string `yaml:"user" json:"user"`
	Password       string `yaml:"password" json:"password"`
	Chpasswd       struct {
		Expire bool `yaml:"expire" json:"expire"`
	} `yaml:"chpasswd" json:"chpasswd"`
	Users []string `yaml:"users" json:"users"`
}

type NetworkConfig struct {
	Version int `yaml:"version" json:"version"`
	Config  []struct {
		Type       string `yaml:"type" json:"type"`
		Name       string `yaml:"name" json:"name"`
		MacAddress string `yaml:"mac_address" json:"mac_address"`
		Subnets    []struct {
			Type    string `yaml:"type" json:"type"`
			Address string `yaml:"address" json:"address"`
			Netmask string `yaml:"netmask" json:"netmask"`
			Gateway string `yaml:"gateway" json:"gateway"`
		} `yaml:"subnets" json:"subnets"`
		Address []string `yaml:"address" json:"address"`
		Search  []string `yaml:"search" json:"search"`
	} `yaml:"config" json:"config"`
}

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

const systemdServiceTemplate = `[Unit]
Description=Cloud-Init NoCloud initialization
DefaultDependencies=no
After=systemd-hostnamed.service
Requires=systemd-hostnamed.service
Before=network.target
ConditionPathExists=!/etc/cloud/cloud-init.disabled

[Service]
Type=oneshot
ExecStart={{.ExecPath}}
RemainAfterExit=yes
StandardOutput=journal+console

[Install]
WantedBy=sysinit.target
`

func netmaskToCIDR(netmask string) (int, error) {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return 0, fmt.Errorf("invalid netmask: %s", netmask)
	}
	cidr, _ := net.IPMask(ip.To4()).Size()
	return cidr, nil
}

var ErrCIDATANotFound = errors.New("CIDATA device not found")

func findCIDATADevice() (string, error) {
	entries, err := os.ReadDir("/dev/disk/by-label")
	if err != nil {
		// On MicroOS early boot, this directory may exist but be unreadable.
		// Treat ALL read errors as "CIDATA not found".
		if os.IsNotExist(err) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EIO) {
			return "", ErrCIDATANotFound
		}
		return "", ErrCIDATANotFound
	}

	for _, e := range entries {
		if strings.EqualFold(e.Name(), "CIDATA") {
			return "/dev/disk/by-label/" + e.Name(), nil
		}
	}

	return "", ErrCIDATANotFound
}

func mountISO(mountPoint string) (string, error) {
	device, err := findCIDATADevice()
	if err != nil {
		if errors.Is(err, ErrCIDATANotFound) {
			return "", ErrCIDATANotFound
		}
		return "", err
	}

	if err := unix.Mount(device, mountPoint, "iso9660", unix.MS_RDONLY, ""); err != nil {
		return "", fmt.Errorf("failed to mount %s: %v", device, err)
	}

	return device, nil
}

func unmountISO(mountPoint string) error {
	if err := unix.Unmount(mountPoint, 0); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", mountPoint, err)
	}
	return nil
}

func updateHostname(hostname string) error {
	cmd := exec.Command("hostnamectl", "set-hostname", hostname)
	return cmd.Run()
}

func updatePassword(user, hashedPassword string) error {
	cmd := exec.Command("usermod", "-p", hashedPassword, user)
	return cmd.Run()
}

func updateResolvConf(nameservers []string, searchDomain string) error {
	if _, err := os.Lstat(resolvConfPath); err == nil {
		if link, err := os.Readlink(resolvConfPath); err == nil {
			return fmt.Errorf("%s is a symlink to %s, cannot edit directly", resolvConfPath, link)
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

	resolvFile, err := os.Create(resolvConfPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %v", resolvConfPath, err)
	}
	defer resolvFile.Close()

	if err := resolvTmpl.Execute(resolvFile, resolvData); err != nil {
		return fmt.Errorf("failed to execute resolv.conf template: %v", err)
	}
	log.Printf("Updated %s with DNS configuration", resolvConfPath)
	return nil
}

func updateHostsFile(userData UserData) error {
	if !userData.ManageEtcHosts {
		return nil
	}

	hostsPath := "/etc/hosts"
	loopbackEntry := fmt.Sprintf("127.0.1.1 %s %s", userData.FQDN, userData.Hostname)

	file, err := os.OpenFile(hostsPath, os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", hostsPath, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		// Drop ALL existing 127.0.1.1 entries
		if strings.HasPrefix(line, "127.0.1.1") {
			continue
		}

		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading %s: %v", hostsPath, err)
	}

	// Prepend the correct entry
	lines = append([]string{loopbackEntry}, lines...)

	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate %s: %v", hostsPath, err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek %s: %v", hostsPath, err)
	}

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %v", hostsPath, err)
	}

	log.Printf("Updated %s with hostname entry", hostsPath)
	return nil
}

func generateSystemdNetworkConfig(config NetworkConfig) error {
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
	for _, iface := range config.Config {
		if iface.Type == "nameserver" {
			nameservers = iface.Address
			searchDomain = strings.Join(iface.Search, " ")
		}
	}

	for _, iface := range config.Config {
		if iface.Type == "physical" {
			if len(iface.Subnets) == 0 {
				continue
			}
			subnet := iface.Subnets[0]

			useDHCP := subnet.Type == "dhcp4"

			var cidr int
			if !useDHCP {
				cidr, err = netmaskToCIDR(subnet.Netmask)
				if err != nil {
					return fmt.Errorf("failed to convert netmask to CIDR: %v", err)
				}
			}

			networkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.network", systemdNetworkDir, iface.Name)
			networkFile, err := os.Create(networkFilePath)
			if err != nil {
				return fmt.Errorf("failed to create network config file for %s: %v", iface.Name, err)
			}
			defer networkFile.Close()

			linkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.link", systemdNetworkDir, iface.Name)
			linkFile, err := os.Create(linkFilePath)
			if err != nil {
				return fmt.Errorf("failed to create link config file for %s: %v", iface.Name, err)
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
				MacAddress: iface.MacAddress,
				Name:       iface.Name,
				Gateway:    subnet.Gateway,
				DHCP:       useDHCP,
			}

			linkData := struct {
				MacAddress string
				Name       string
			}{
				MacAddress: iface.MacAddress,
				Name:       iface.Name,
			}

			if err := networkTmpl.Execute(networkFile, networkData); err != nil {
				return fmt.Errorf("failed to execute network template for %s: %v", iface.Name, err)
			}
			log.Printf("Generated systemd-networkd config for interface %s at %s", iface.Name, networkFilePath)

			if err := linkTmpl.Execute(linkFile, linkData); err != nil {
				return fmt.Errorf("failed to execute link template for %s: %v", iface.Name, err)
			}
			log.Printf("Generated systemd-networkd link config for interface %s at %s", iface.Name, linkFilePath)
		}
	}

	if err := updateResolvConf(nameservers, searchDomain); err != nil {
		return fmt.Errorf("failed to update /etc/resolv.conf: %v", err)
	}

	return nil
}

func installService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	servicePath := fmt.Sprintf("%s/%s.service", systemdServiceDir, serviceName)
	serviceFile, err := os.Create(servicePath)
	if err != nil {
		return fmt.Errorf("failed to create service file: %v", err)
	}
	defer serviceFile.Close()

	tmpl, err := template.New("systemdService").Parse(systemdServiceTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse systemd service template: %v", err)
	}

	data := struct {
		ExecPath    string
		ServiceName string
	}{
		ExecPath:    execPath,
		ServiceName: serviceName,
	}

	if err := tmpl.Execute(serviceFile, data); err != nil {
		return fmt.Errorf("failed to execute systemd service template: %v", err)
	}

	log.Printf("Installed systemd service at %s", servicePath)

	// Attempt DBus connection (optional)
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Printf("Warning: Could not connect to system bus (DBus unavailable?).")
		log.Printf("You may need to enable the service manually:")
		log.Printf("  systemctl enable %s.service", serviceName)
		return nil
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	call := obj.Call("org.freedesktop.systemd1.Manager.EnableUnitFiles", 0,
		[]string{fmt.Sprintf("%s.service", serviceName)}, false, true)

	if call.Err != nil {
		log.Printf("Warning: Could not enable the service automatically (DBus unavailable?).")
		log.Printf("You may need to enable it manually:")
		log.Printf("  systemctl enable %s.service", serviceName)
		return nil
	}

	log.Printf("Installed and Enabled %s", serviceName)
	return nil
}

func checkAndGenerateSSHKeys() error {
	if _, err := os.Stat(sshKeyPath); os.IsNotExist(err) {
		log.Println("SSH host key not found, generating new keys...")
		cmd := exec.Command("ssh-keygen", "-A")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to generate SSH host keys: %v", err)
		}
		log.Println("Generated missing SSH host keys")
	} else if err != nil {
		return fmt.Errorf("failed to check SSH host key existence: %v", err)
	}
	return nil
}

func checkPrograms() error {
	for _, program := range requiredPrograms {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("required program %s is not installed", program)
		}
		log.Printf("Program %s is available", program)
	}
	return nil
}

func checkDirectories() error {
	for _, dir := range requiredDirectories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("required directory %s does not exist", dir)
		}
		log.Printf("Directory %s exists", dir)
	}
	return nil
}

func unmarshalUserData(data []byte, ud *UserData) error {
	if err := yaml.Unmarshal(data, ud); err == nil {
		return nil
	}
	yamlErr := yaml.Unmarshal(data, ud)
	if err := json.Unmarshal(data, ud); err == nil {
		return nil
	}
	return yamlErr
}

func unmarshalNetworkConfig(data []byte, nc *NetworkConfig) error {
	if err := yaml.Unmarshal(data, nc); err == nil {
		return nil
	}
	yamlErr := yaml.Unmarshal(data, nc)
	if err := json.Unmarshal(data, nc); err == nil {
		return nil
	}
	return yamlErr
}

func main() {
	log.SetFlags(0)

	helpFlag := pflag.BoolP("help", "h", false, "Display help information")
	versionFlag := pflag.BoolP("version", "V", false, "Display version information")
	installFlag := pflag.BoolP("install", "i", false, "Install systemd service")
	pflag.Parse()

	if *helpFlag {
		helpText := fmt.Sprintf(`%s %s
%s

Options:
  -h, --help       Display help information
  -i, --install    Install systemd service
  -V, --version    Display version information`,
			serviceName, __VERSION__, serviceDescription)

		fmt.Println(helpText)
		return
	}

	if *versionFlag {
		fmt.Printf("%s version %s\n", serviceName, __VERSION__)
		return
	}

	if *installFlag {
		if err := checkPrograms(); err != nil {
			log.Fatalf("Failed to check required programs: %v", err)
		}
		if err := checkDirectories(); err != nil {
			log.Fatalf("Failed to check required directories: %v", err)
		}
		if err := installService(); err != nil {
			log.Fatalf("Failed to install systemd service: %v", err)
		}
		return
	}

	log.Printf("Starting %s...", serviceName)

	mountDir, err := os.MkdirTemp("", "cloud-init-")
	if err != nil {
		log.Fatalf("Failed to create temporary directory: %v", err)
	}

	// Only remove the directory if we never mounted anything
	mounted := false
	defer func() {
		if !mounted {
			if err := os.RemoveAll(mountDir); err != nil {
				log.Printf("Failed to remove temporary directory %s: %v", mountDir, err)
			}
		}
	}()

	// Graceful CIDATA-missing handling
	if _, err := mountISO(mountDir); err != nil {
		if errors.Is(err, ErrCIDATANotFound) {
			log.Printf("No CIDATA device found; skipping cloud-init.")
			return
		}
		log.Fatalf("Failed to mount ISO to %s: %v", mountDir, err)
	}
	mounted = true

	defer func() {
		if err := unmountISO(mountDir); err != nil {
			log.Printf("Failed to unmount %s: %v", mountDir, err)
		}
		if err := os.RemoveAll(mountDir); err != nil {
			log.Printf("Failed to remove temporary directory %s: %v", mountDir, err)
		}
	}()

	log.Printf("Mounted device with CIDATA label to %s", mountDir)

	userDataPath := mountDir + "/user-data"
	userDataContent, err := os.ReadFile(userDataPath)
	if err != nil {
		log.Fatalf("Failed to read user-data from %s: %v", userDataPath, err)
	}
	log.Printf("Read user-data from %s", userDataPath)

	var userData UserData
	if err := unmarshalUserData(userDataContent, &userData); err != nil {
		log.Fatalf("Failed to parse user-data: %v", err)
	}
	safeUserData := userData
	if safeUserData.Password != "" {
		safeUserData.Password = "[REDACTED]"
	}
	log.Printf("Parsed user-data: %+v", safeUserData)

	if err := updateHostname(userData.Hostname); err != nil {
		log.Fatalf("Failed to update hostname: %v", err)
	}
	log.Printf("Updated hostname to %s", userData.Hostname)

	if err := updatePassword(userData.User, userData.Password); err != nil {
		log.Fatalf("Failed to update password for user %s: %v", userData.User, err)
	}
	log.Printf("Updated password for user %s", userData.User)

	if err := updateHostsFile(userData); err != nil {
		log.Fatalf("Failed to update /etc/hosts: %v", err)
	}

	networkConfigPath := mountDir + "/network-config"
	networkConfigData, err := os.ReadFile(networkConfigPath)
	if err != nil {
		log.Fatalf("Failed to read network-config from %s: %v", networkConfigPath, err)
	}
	log.Printf("Read network-config from %s", networkConfigPath)

	var networkConfig NetworkConfig
	if err := unmarshalNetworkConfig(networkConfigData, &networkConfig); err != nil {
		log.Fatalf("Failed to parse network-config: %v", err)
	}
	log.Printf("Parsed network-config: %+v", networkConfig)

	if err := generateSystemdNetworkConfig(networkConfig); err != nil {
		log.Fatalf("Failed to generate systemd-networkd config: %v", err)
	}

	if err := checkAndGenerateSSHKeys(); err != nil {
		log.Fatalf("Failed to check and generate SSH keys: %v", err)
	}

	log.Printf("Completed %s execution successfully", serviceName)
}
