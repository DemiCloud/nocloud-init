package service

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"text/template"
)

const ServiceName = "nocloud-init"
const ServiceDescription = "A Cloud-init client for NoCloud"

const systemdServiceDir = "/etc/systemd/system"
const systemdNetworkDir = "/etc/systemd/network"

const systemdServiceTemplate = `[Unit]
Description=Cloud-Init NoCloud initialization
Documentation=https://github.com/demicloud/nocloud-init
DefaultDependencies=no

# /etc and block devices must exist
After=local-fs.target

# Run before udev settles NIC naming
Before=systemd-udev-settle.service

# Run before networkd consumes link/network files
Before=systemd-networkd.service
Before=network-pre.target
Before=network.target
Before=network-online.target

ConditionPathExists=!/etc/cloud/cloud-init.disabled

[Service]
Type=oneshot
ExecStart={{.ExecPath}}
RemainAfterExit=yes
StandardOutput=journal+console

PrivateTmp=true
NoNewPrivileges=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true

[Install]
WantedBy=sysinit.target
`

var requiredPrograms = []string{
	"usermod",
	"ssh-keygen",
}

var requiredDirectories = []string{
	systemdNetworkDir,
}

func InstallService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	servicePath := fmt.Sprintf("%s/%s.service", systemdServiceDir, ServiceName)
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
		ServiceName: ServiceName,
	}

	if err := tmpl.Execute(serviceFile, data); err != nil {
		return fmt.Errorf("failed to execute systemd service template: %v", err)
	}

	slog.Info("installed systemd service", "path", servicePath)

	cmd := exec.Command("systemctl", "enable", ServiceName+".service")
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("could not enable service automatically, enable manually",
			"command", "systemctl enable "+ServiceName+".service",
			"error", string(out))
		return nil
	}

	slog.Info("installed and enabled service", "service", ServiceName)
	return nil
}

func CheckPrograms() error {
	for _, program := range requiredPrograms {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("required program %s is not installed", program)
		}
		slog.Debug("program available", "program", program)
	}
	return nil
}

func CheckDirectories() error {
	for _, dir := range requiredDirectories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("required directory %s does not exist", dir)
		}
		slog.Debug("directory exists", "dir", dir)
	}
	return nil
}
