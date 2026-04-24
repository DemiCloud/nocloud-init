package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/pflag"

	"github.com/demicloud/nocloud-init/internal/mount"
	"github.com/demicloud/nocloud-init/internal/network"
	"github.com/demicloud/nocloud-init/internal/service"
	"github.com/demicloud/nocloud-init/internal/system"
	"github.com/demicloud/nocloud-init/internal/types"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func printVersion() {
	fmt.Printf("%s %s\n", service.ServiceName, version)
	fmt.Printf("commit:    %s\n", commit)
	fmt.Printf("built:     %s\n", date)
	fmt.Printf("builtBy:   %s\n", builtBy)
	fmt.Printf("go:        %s\n", runtime.Version())
	fmt.Printf("os/arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
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
			service.ServiceName, version, service.ServiceDescription)

		fmt.Println(helpText)
		return
	}

	if *versionFlag {
		printVersion()
		return
	}

	if *installFlag {
		if err := service.CheckPrograms(); err != nil {
			log.Fatalf("Failed to check required programs: %v", err)
		}
		if err := service.CheckDirectories(); err != nil {
			log.Fatalf("Failed to check required directories: %v", err)
		}
		if err := service.InstallService(); err != nil {
			log.Fatalf("Failed to install systemd service: %v", err)
		}
		return
	}

	log.Printf("Starting %s...", service.ServiceName)

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
	device, err := mount.MountISO(mountDir)
	if err != nil {
		if errors.Is(err, mount.ErrCIDATANotFound) {
			log.Printf("No CIDATA device found; skipping cloud-init.")
			return
		}
		log.Fatalf("Failed to mount ISO to %s: %v", mountDir, err)
	}
	log.Printf("Mounted CIDATA device %s at %s", device, mountDir)
	mounted = true

	defer func() {
		if err := mount.UnmountISO(mountDir); err != nil {
			log.Printf("Failed to unmount %s: %v", mountDir, err)
		}
		if err := os.RemoveAll(mountDir); err != nil {
			log.Printf("Failed to remove temporary directory %s: %v", mountDir, err)
		}
	}()

	log.Printf("Mounted device with CIDATA label to %s", mountDir)

	userDataPath := filepath.Join(mountDir, "user-data")
	var userData types.UserData
	userDataContent, err := os.ReadFile(userDataPath)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to read user-data from %s: %v", userDataPath, err)
	}
	if err == nil {
		log.Printf("Read user-data from %s", userDataPath)

		if err := types.UnmarshalUserData(userDataContent, &userData); err != nil {
			log.Fatalf("Failed to parse user-data: %v", err)
		}
		safeUserData := userData
		if safeUserData.Password != "" {
			safeUserData.Password = "[REDACTED]"
		}
		log.Printf("Parsed user-data: %+v", safeUserData)
	} else {
		log.Printf("No user-data found at %s, skipping user-data configuration", userDataPath)
	}

	if userData.Hostname != "" && !system.IsValidHostname(userData.Hostname) {
		log.Fatalf("Invalid hostname %q: must contain only letters, digits, hyphens, and dots", userData.Hostname)
	}
	if userData.FQDN != "" && !system.IsValidHostname(userData.FQDN) {
		log.Fatalf("Invalid fqdn %q: must contain only letters, digits, hyphens, and dots", userData.FQDN)
	}

	if userData.Hostname != "" {
		if err := system.UpdateHostname(userData.Hostname); err != nil {
			log.Fatalf("Failed to update hostname: %v", err)
		}
		log.Printf("Updated hostname to %s", userData.Hostname)
	}

	if userData.User != "" && userData.Password != "" {
		if err := system.UpdatePassword(userData.User, userData.Password); err != nil {
			log.Fatalf("Failed to update password for user %s: %v", userData.User, err)
		}
		log.Printf("Updated password for user %s", userData.User)
	}

	if err := system.UpdateHostsFile(userData); err != nil {
		log.Fatalf("Failed to update /etc/hosts: %v", err)
	}

	networkConfigPath := filepath.Join(mountDir, "network-config")
	networkConfigData, err := os.ReadFile(networkConfigPath)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Failed to read network-config from %s: %v", networkConfigPath, err)
	}
	if err == nil {
		log.Printf("Read network-config from %s", networkConfigPath)

		var networkConfig types.NetworkConfig
		if err := types.UnmarshalNetworkConfig(networkConfigData, &networkConfig); err != nil {
			log.Fatalf("Failed to parse network-config: %v", err)
		}
		log.Printf("Parsed network-config: %+v", networkConfig)

		if err := network.GenerateSystemdNetworkConfig(networkConfig); err != nil {
			log.Fatalf("Failed to generate systemd-networkd config: %v", err)
		}
	} else {
		log.Printf("No network-config found at %s, skipping network configuration", networkConfigPath)
	}

	if err := system.CheckAndGenerateSSHKeys(); err != nil {
		log.Fatalf("Failed to check and generate SSH keys: %v", err)
	}

	log.Printf("Completed %s execution successfully", service.ServiceName)
}
