package service

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"

	"github.com/godbus/dbus/v5"
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

	log.Printf("Installed systemd service at %s", servicePath)

	// Attempt DBus connection (optional)
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Printf("Warning: Could not connect to system bus (DBus unavailable?).")
		log.Printf("You may need to enable the service manually:")
		log.Printf("  systemctl enable %s.service", ServiceName)
		return nil
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	call := obj.Call("org.freedesktop.systemd1.Manager.EnableUnitFiles", 0,
		[]string{fmt.Sprintf("%s.service", ServiceName)}, false, true)

	if call.Err != nil {
		log.Printf("Warning: Could not enable the service automatically (DBus unavailable?).")
		log.Printf("You may need to enable it manually:")
		log.Printf("  systemctl enable %s.service", ServiceName)
		return nil
	}

	log.Printf("Installed and Enabled %s", ServiceName)
	return nil
}

func CheckPrograms() error {
	for _, program := range requiredPrograms {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("required program %s is not installed", program)
		}
		log.Printf("Program %s is available", program)
	}
	return nil
}

func CheckDirectories() error {
	for _, dir := range requiredDirectories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("required directory %s does not exist", dir)
		}
		log.Printf("Directory %s exists", dir)
	}
	return nil
}
