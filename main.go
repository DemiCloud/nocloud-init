package main

import (
    "fmt"
    "log"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "text/template"

    "github.com/godbus/dbus/v5"
    "github.com/spf13/pflag"
    "github.com/vishvananda/netlink"
    "gopkg.in/yaml.v2"
)

const (
    __VERSION__        = "0.18.0"
    serviceName        = "nocloud-init"
    serviceDescription = "A Cloud-init client for NoCloud"

    systemdNetworkDir = "/etc/systemd/network"
    systemdServiceDir = "/etc/systemd/system"
    sshKeyPath        = "/etc/ssh/ssh_host_rsa_key"
    resolvConfPath    = "/etc/resolv.conf"
)

var requiredPrograms = []string{
    "networkctl",
    "usermod",
    "hostnamectl",
    "ssh-keygen",
    "blkid",
    "mount",
    "umount",
}

var requiredDirectories = []string{
    systemdNetworkDir,
}

type UserData struct {
    Hostname       string `yaml:"hostname"`
    ManageEtcHosts bool   `yaml:"manage_etc_hosts"`
    FQDN           string `yaml:"fqdn"`
    User           string `yaml:"user"`
    Password       string `yaml:"password"`
    Chpasswd       struct {
        Expire bool `yaml:"expire"`
    } `yaml:"chpasswd"`
    Users []string `yaml:"users"`
}

type NetworkConfig struct {
    Version int `yaml:"version"`
    Config  []struct {
        Type       string   `yaml:"type"`
        Name       string   `yaml:"name"`
        MacAddress string   `yaml:"mac_address"`
        Subnets    []struct {
            Type    string `yaml:"type"`
            Address string `yaml:"address"`
            Netmask string `yaml:"netmask"`
            Gateway string `yaml:"gateway"`
        } `yaml:"subnets"`
        Address []string `yaml:"address"`
        Search  []string `yaml:"search"`
    } `yaml:"config"`
}

type Hostnames struct {
    Short string
    FQDN  string
}

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

const resolvConfTemplate = `search {{.SearchDomain}}
{{range .Nameservers}}nameserver {{.}}
{{end}}options edns0 trust-ad
`

const systemdServiceTemplate = `[Unit]
Description={{.ServiceName}} service
DefaultDependencies=no
After=local-fs.target systemd-hostnamed.service
Requires=systemd-hostnamed.service
Before=network-pre.target
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

func findDeviceByLabel(labels []string) (string, error) {
    var lastErr error
    for _, label := range labels {
        cmd := exec.Command("blkid", "-L", label)
        output, err := cmd.Output()
        if err == nil {
            device := strings.TrimSpace(string(output))
            if device != "" {
                return device, nil
            }
        }
        lastErr = err
    }
    if lastErr != nil {
        return "", fmt.Errorf("device with labels %v not found: %v", labels, lastErr)
    }
    return "", fmt.Errorf("device with labels %v not found", labels)
}

func mountISO(mountPoint string) error {
    device, err := findDeviceByLabel([]string{"CIDATA", "cidata"})
    if err != nil {
        return err
    }
    cmd := exec.Command("mount", "-t", "iso9660", device, mountPoint)
    return cmd.Run()
}

func unmountISO(mountPoint string) error {
    cmd := exec.Command("umount", mountPoint)
    return cmd.Run()
}

func deriveHostnames(u UserData) (Hostnames, error) {
    h := strings.TrimSpace(u.Hostname)
    f := strings.TrimSpace(u.FQDN)

    // If fqdn is set and contains a dot, trust it as canonical.
    if f != "" && strings.Contains(f, ".") {
        short := h
        if short == "" {
            if i := strings.IndexByte(f, '.'); i > 0 {
                short = f[:i]
            } else {
                short = f
            }
        }
        return Hostnames{Short: short, FQDN: f}, nil
    }

    // If fqdn is set but has no dot and hostname is empty, treat fqdn as short.
    if f != "" && !strings.Contains(f, ".") && h == "" {
        return Hostnames{Short: f, FQDN: ""}, nil
    }

    // If hostname looks like an FQDN and fqdn is empty, derive short from hostname.
    if h != "" && strings.Contains(h, ".") && f == "" {
        if i := strings.IndexByte(h, '.'); i > 0 {
            return Hostnames{Short: h[:i], FQDN: h}, nil
        }
        return Hostnames{Short: h, FQDN: ""}, nil
    }

    // Simple case: short hostname only.
    if h != "" && f == "" {
        return Hostnames{Short: h, FQDN: ""}, nil
    }

    // fqdn set, hostname set but fqdn has no dot: treat hostname as canonical.
    if h != "" && f != "" && !strings.Contains(f, ".") {
        return Hostnames{Short: h, FQDN: ""}, nil
    }

    if h == "" && f == "" {
        return Hostnames{}, fmt.Errorf("no hostname or fqdn provided")
    }

    return Hostnames{Short: h, FQDN: f}, nil
}

func updateHostname(h Hostnames) error {
    name := h.FQDN
    if name == "" {
        name = h.Short
    }
    if name == "" {
        return fmt.Errorf("no hostname to set")
    }
    cmd := exec.Command("hostnamectl", "set-hostname", name)
    return cmd.Run()
}

func updatePassword(user, hashedPassword string) error {
    cmd := exec.Command("usermod", "-p", hashedPassword, user)
    return cmd.Run()
}

func renameInterfaceByMAC(macAddress, newName string) error {
    links, err := netlink.LinkList()
    if err != nil {
        return fmt.Errorf("failed to list network interfaces: %v", err)
    }

    var targetLink netlink.Link
    for _, link := range links {
        if strings.EqualFold(link.Attrs().HardwareAddr.String(), macAddress) {
            targetLink = link
            break
        }
    }

    if targetLink == nil {
        return fmt.Errorf("failed to find interface with MAC %s: Link not found", macAddress)
    }

    if err := netlink.LinkSetName(targetLink, newName); err != nil {
        return fmt.Errorf("failed to rename interface with MAC %s to %s: %v", macAddress, newName, err)
    }
    log.Printf("Renamed interface with MAC %s to %s", macAddress, newName)
    return nil
}

func updateResolvConf(nameservers []string, searchDomain string) error {
    if len(nameservers) == 0 && strings.TrimSpace(searchDomain) == "" {
        log.Printf("No DNS configuration in network-config; leaving %s unchanged", resolvConfPath)
        return nil
    }

    if fi, err := os.Lstat(resolvConfPath); err == nil && (fi.Mode()&os.ModeSymlink) != 0 {
        if link, err := os.Readlink(resolvConfPath); err == nil {
            log.Printf("%s is a symlink to %s; skipping direct DNS management", resolvConfPath, link)
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

    h, err := deriveHostnames(userData)
    if err != nil {
        return err
    }

    hostsPath := "/etc/hosts"

    var loopbackEntry string
    switch {
    case h.FQDN != "" && h.Short != "":
        loopbackEntry = fmt.Sprintf("127.0.1.1 %s %s", h.FQDN, h.Short)
    case h.FQDN != "":
        loopbackEntry = fmt.Sprintf("127.0.1.1 %s", h.FQDN)
    default:
        loopbackEntry = fmt.Sprintf("127.0.1.1 %s", h.Short)
    }

    orig, err := os.ReadFile(hostsPath)
    if err != nil {
        return fmt.Errorf("failed to read %s: %v", hostsPath, err)
    }

    st, err := os.Stat(hostsPath)
    if err != nil {
        return fmt.Errorf("failed to stat %s: %v", hostsPath, err)
    }

    lines := strings.Split(string(orig), "\n")
    out := make([]string, 0, len(lines)+1)

    // Our canonical entry first.
    out = append(out, loopbackEntry)

    for _, line := range lines {
        l := strings.TrimSpace(line)
        if l == "" {
            continue
        }
        if strings.HasPrefix(l, "#") {
            out = append(out, line)
            continue
        }
        fields := strings.Fields(l)
        if len(fields) > 0 && fields[0] == "127.0.1.1" {
            // Drop all existing 127.0.1.1 entries.
            continue
        }
        out = append(out, line)
    }

    newContent := strings.Join(out, "\n") + "\n"
    tmp := hostsPath + ".nocloud-init.tmp"

    if err := os.WriteFile(tmp, []byte(newContent), st.Mode()); err != nil {
        return fmt.Errorf("failed to write temp hosts file: %v", err)
    }
    if err := os.Rename(tmp, hostsPath); err != nil {
        return fmt.Errorf("failed to replace %s: %v", hostsPath, err)
    }

    log.Printf("Updated %s with hostname entry: %s", hostsPath, loopbackEntry)
    return nil
}

func cleanupOldNetworkConfigs() {
    patterns := []string{
        filepath.Join(systemdNetworkDir, "10-cloud-init-*.network"),
        filepath.Join(systemdNetworkDir, "10-cloud-init-*.link"),
    }
    for _, pattern := range patterns {
        matches, _ := filepath.Glob(pattern)
        for _, m := range matches {
            if err := os.Remove(m); err != nil {
                log.Printf("Warning: failed to remove old network config %s: %v", m, err)
            }
        }
    }
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

    // Clean up old configs first.
    cleanupOldNetworkConfigs()

    var nameservers []string
    var searchDomain string
    for _, iface := range config.Config {
        if iface.Type == "nameserver" {
            nameservers = iface.Address
            searchDomain = strings.Join(iface.Search, " ")
        }
    }

    for _, iface := range config.Config {
        if iface.Type != "physical" {
            continue
        }

        if len(iface.Subnets) == 0 {
            return fmt.Errorf("interface %s has no subnets", iface.Name)
        }
        subnet := iface.Subnets[0]

        useDHCP := strings.HasPrefix(subnet.Type, "dhcp")

        var cidr int
        if !useDHCP {
            if subnet.Netmask == "" || subnet.Address == "" {
                return fmt.Errorf("interface %s static config missing address or netmask", iface.Name)
            }
            cidr, err = netmaskToCIDR(subnet.Netmask)
            if err != nil {
                return fmt.Errorf("failed to convert netmask to CIDR for %s: %v", iface.Name, err)
            }
        }

        networkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.network", systemdNetworkDir, iface.Name)
        networkFile, err := os.Create(networkFilePath)
        if err != nil {
            return fmt.Errorf("failed to create network config file for %s: %v", iface.Name, err)
        }

        linkFilePath := fmt.Sprintf("%s/10-cloud-init-%s.link", systemdNetworkDir, iface.Name)
        linkFile, err := os.Create(linkFilePath)
        if err != nil {
            networkFile.Close()
            return fmt.Errorf("failed to create link config file for %s: %v", iface.Name, err)
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
            networkFile.Close()
            linkFile.Close()
            return fmt.Errorf("failed to execute network template for %s: %v", iface.Name, err)
        }
        log.Printf("Generated systemd-networkd config for interface %s at %s", iface.Name, networkFilePath)

        if err := linkTmpl.Execute(linkFile, linkData); err != nil {
            networkFile.Close()
            linkFile.Close()
            return fmt.Errorf("failed to execute link template for %s: %v", iface.Name, err)
        }
        log.Printf("Generated systemd-networkd link config for interface %s at %s", iface.Name, linkFilePath)

        networkFile.Close()
        linkFile.Close()
    }

    if err := updateResolvConf(nameservers, searchDomain); err != nil {
        return fmt.Errorf("failed to update /etc/resolv.conf: %v", err)
    }

    // Reload systemd-networkd so changes take effect.
    if err := exec.Command("networkctl", "reload").Run(); err != nil {
        log.Printf("Warning: failed to reload systemd-networkd: %v", err)
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

    conn, err := dbus.SystemBus()
    if err != nil {
        return fmt.Errorf("failed to connect to system bus: %v", err)
    }
    defer conn.Close()

    obj := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
    call := obj.Call("org.freedesktop.systemd1.Manager.EnableUnitFiles", 0, []string{fmt.Sprintf("%s.service", serviceName)}, false, true)
    if call.Err != nil {
        return fmt.Errorf("failed to enable systemd service via D-Bus: %v", call.Err)
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
    defer func() {
        if err := os.RemoveAll(mountDir); err != nil {
            log.Printf("Failed to remove temporary directory %s: %v", mountDir, err)
        }
    }()

    if err := mountISO(mountDir); err != nil {
        log.Fatalf("Failed to mount ISO to %s: %v", mountDir, err)
    }
    defer func() {
        if err := unmountISO(mountDir); err != nil {
            log.Printf("Failed to unmount %s: %v", mountDir, err)
        }
    }()
    log.Printf("Mounted device with CIDATA label to %s", mountDir)

    userDataPath := filepath.Join(mountDir, "user-data")
    userDataContent, err := os.ReadFile(userDataPath)
    if err != nil {
        log.Fatalf("Failed to read user-data from %s: %v", userDataPath, err)
    }
    log.Printf("Read user-data from %s", userDataPath)

    var userData UserData
    if err := yaml.Unmarshal(userDataContent, &userData); err != nil {
        log.Fatalf("Failed to parse user-data: %v", err)
    }
    log.Printf("Parsed user-data: hostname=%q fqdn=%q manage_etc_hosts=%v user=%q",
        userData.Hostname, userData.FQDN, userData.ManageEtcHosts, userData.User)

    hostnames, err := deriveHostnames(userData)
    if err != nil {
        log.Fatalf("Failed to derive hostnames: %v", err)
    }

    if err := updateHostname(hostnames); err != nil {
        log.Fatalf("Failed to update hostname: %v", err)
    }
    log.Printf("Updated hostname to short=%q fqdn=%q", hostnames.Short, hostnames.FQDN)

    if err := updatePassword(userData.User, userData.Password); err != nil {
        log.Fatalf("Failed to update password for user %s: %v", userData.User, err)
    }
    log.Printf("Updated password for user %s", userData.User)

    if err := updateHostsFile(userData); err != nil {
        log.Fatalf("Failed to update /etc/hosts: %v", err)
    }

    networkConfigPath := filepath.Join(mountDir, "network-config")
    networkConfigData, err := os.ReadFile(networkConfigPath)
    if err != nil {
        log.Fatalf("Failed to read network-config from %s: %v", networkConfigPath, err)
    }
    log.Printf("Read network-config from %s", networkConfigPath)

    var networkConfig NetworkConfig
    if err := yaml.Unmarshal(networkConfigData, &networkConfig); err != nil {
        log.Fatalf("Failed to parse network-config: %v", err)
    }
    log.Printf("Parsed network-config: version=%d entries=%d", networkConfig.Version, len(networkConfig.Config))

    if err := generateSystemdNetworkConfig(networkConfig); err != nil {
        log.Fatalf("Failed to generate systemd-networkd config: %v", err)
    }

    if err := checkAndGenerateSSHKeys(); err != nil {
        log.Fatalf("Failed to check and generate SSH keys: %v", err)
    }

    log.Printf("Completed %s execution successfully", serviceName)
}

