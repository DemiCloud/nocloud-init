package service

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"text/template"
)

const ServiceName = "nocloud-init"
const ServiceDescription = "A Cloud-init client for NoCloud"

const systemdServiceDir = "/etc/systemd/system"
const systemdNetworkDir = "/etc/systemd/network"

const systemdServiceTemplate = `[Unit]
Description={{.ServiceDescription}}
Documentation=https://github.com/demicloud/nocloud-init
DefaultDependencies=no

# /etc and block device symlinks (/dev/disk/by-label) must be available
After=local-fs.target

# Write .link files before udev settles NIC naming
Before=systemd-udev-settle.service

# Write .network/.link files before networkd reads its config
Before=systemd-networkd.service

# Ordering relative to network milestones
Before=network-pre.target
Before=network.target
Before=network-online.target

ConditionPathExists=!/etc/cloud/cloud-init.disabled

[Service]
Type=oneshot
ExecStart={{.ExecPath}}
RemainAfterExit=yes
StandardOutput=journal+console

# Filesystem hardening — /etc is whitelisted for writes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/etc
ProtectHome=yes

# Privilege hardening
NoNewPrivileges=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes

# Kernel hardening
ProtectClock=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes

# Capability hardening — explicit allowlist restricted to what this service needs:
#   CAP_SYS_ADMIN     mount(2), umount(2), sethostname(2)
#   CAP_CHOWN         set ownership of files written to /etc
#   CAP_DAC_OVERRIDE  write to files not owned by running user
#   CAP_FOWNER        bypass owner checks (chmod, utimes) on /etc files
#   CAP_SETGID        chpasswd subprocess may adjust group identity
#   CAP_SETUID        chpasswd subprocess may adjust user identity
#   CAP_SETPCAP       capability manipulation in child processes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID CAP_SETPCAP

# Hostname — intentionally changed via sethostname(2); must not be restricted.
ProtectHostname=no

# Devices — block device access required for CIDATA ISO mount; cannot restrict.
PrivateDevices=no

# Network — all operations are purely local; no sockets of any kind are needed.
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any

# Memory — static CGO_ENABLED=0 Go binary; writable-executable mappings not needed.
MemoryDenyWriteExecute=yes

# System call allowlist — restrict to calls actually made by this service.
# @system-service covers read/write/open/close/stat/mmap/fork/exec and related.
# sethostname, mount, and umount2 are used directly but outside @system-service.
SystemCallFilter=@system-service sethostname mount umount2
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# File creation mask — new files must not be world-readable by default.
UMask=0027

[Install]
WantedBy=network-pre.target
`

var requiredPrograms = []string{
	"chpasswd",
	"ssh-keygen",
}

var requiredDirectories = []string{
	systemdNetworkDir,
	systemdServiceDir,
}

func InstallService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	tmpl, err := template.New("systemdService").Parse(systemdServiceTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse systemd service template: %v", err)
	}

	data := struct {
		ExecPath           string
		ServiceDescription string
	}{
		ExecPath:           execPath,
		ServiceDescription: ServiceDescription,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute systemd service template: %v", err)
	}

	servicePath := fmt.Sprintf("%s/%s.service", systemdServiceDir, ServiceName)
	if err := os.WriteFile(servicePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	fmt.Printf("Installed service file: %s\n", servicePath)

	cmd := exec.Command("systemctl", "enable", ServiceName+".service")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: could not enable service automatically.\n")
		fmt.Printf("Enable it manually with: systemctl enable %s.service\n", ServiceName)
		if len(out) > 0 {
			fmt.Printf("systemctl output: %s\n", out)
		}
		return nil
	}

	fmt.Printf("Enabled %s.service\n", ServiceName)
	return nil
}

func CheckPrograms() error {
	for _, program := range requiredPrograms {
		path, err := exec.LookPath(program)
		if err != nil {
			return fmt.Errorf("required program %s is not installed", program)
		}
		fmt.Printf("  %-12s %s\n", program, path)
	}
	return nil
}

func CheckDirectories() error {
	for _, dir := range requiredDirectories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("required directory %s does not exist", dir)
		}
		fmt.Printf("  %s\n", dir)
	}
	return nil
}
