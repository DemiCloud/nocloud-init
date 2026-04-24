package main

import (
	"errors"
	"fmt"
	"log/slog"
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
	helpFlag := pflag.BoolP("help", "h", false, "Display help information")
	versionFlag := pflag.BoolP("version", "V", false, "Display version information")
	installFlag := pflag.BoolP("install", "i", false, "Install systemd service")
	verboseFlag := pflag.BoolP("verbose", "v", false, "Enable verbose (debug) logging")
	strictFlag := pflag.BoolP("strict", "s", false, "Reject unknown fields in user-data and network-config")
	pflag.Parse()

	logLevel := slog.LevelInfo
	if *verboseFlag {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))

	if *helpFlag {
		helpText := fmt.Sprintf(`%s %s
%s

Options:
  -h, --help       Display help information
  -i, --install    Install systemd service
  -s, --strict     Reject unknown fields in user-data and network-config
  -v, --verbose    Enable verbose (debug) logging
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
			slog.Error("failed to check required programs", "error", err)
			os.Exit(1)
		}
		if err := service.CheckDirectories(); err != nil {
			slog.Error("failed to check required directories", "error", err)
			os.Exit(1)
		}
		if err := service.InstallService(); err != nil {
			slog.Error("failed to install systemd service", "error", err)
			os.Exit(1)
		}
		return
	}

	slog.Info("starting", "service", service.ServiceName)

	mountDir, err := os.MkdirTemp("", "cloud-init-")
	if err != nil {
		slog.Error("failed to create temporary directory", "error", err)
		os.Exit(1)
	}

	// Only remove the directory if we never mounted anything
	mounted := false
	defer func() {
		if !mounted {
			if err := os.RemoveAll(mountDir); err != nil {
				slog.Warn("failed to remove temporary directory", "path", mountDir, "error", err)
			}
		}
	}()

	// Graceful CIDATA-missing handling
	device, err := mount.MountISO(mountDir)
	if err != nil {
		if errors.Is(err, mount.ErrCIDATANotFound) {
			slog.Info("no CIDATA device found, skipping")
			return
		}
		slog.Error("failed to mount ISO", "mountPoint", mountDir, "error", err)
		os.Exit(1)
	}
	slog.Info("mounted CIDATA device", "device", device, "mountPoint", mountDir)
	mounted = true

	defer func() {
		if err := mount.UnmountISO(mountDir); err != nil {
			slog.Warn("failed to unmount", "path", mountDir, "error", err)
		}
		if err := os.RemoveAll(mountDir); err != nil {
			slog.Warn("failed to remove temporary directory", "path", mountDir, "error", err)
		}
	}()

	userDataPath := filepath.Join(mountDir, "user-data")
	var userData types.UserData
	userDataContent, err := os.ReadFile(userDataPath)
	if err != nil && !os.IsNotExist(err) {
		slog.Error("failed to read user-data", "path", userDataPath, "error", err)
		os.Exit(1)
	}
	if err == nil {
		slog.Info("read user-data", "path", userDataPath)

		if err := types.UnmarshalUserData(userDataContent, &userData, *strictFlag); err != nil {
			slog.Error("failed to parse user-data", "error", err)
			os.Exit(1)
		}
		safeUserData := userData
		if safeUserData.Password != "" {
			safeUserData.Password = "[REDACTED]"
		}
		slog.Debug("parsed user-data", "userData", safeUserData)
	} else {
		slog.Info("no user-data found, skipping", "path", userDataPath)
	}

	if userData.Hostname != "" && !system.IsValidHostname(userData.Hostname) {
		slog.Error("invalid hostname", "hostname", userData.Hostname)
		os.Exit(1)
	}
	if userData.FQDN != "" && !system.IsValidHostname(userData.FQDN) {
		slog.Error("invalid FQDN", "fqdn", userData.FQDN)
		os.Exit(1)
	}

	if userData.Hostname != "" {
		if err := system.UpdateHostname(userData.Hostname); err != nil {
			slog.Error("failed to update hostname", "error", err)
			os.Exit(1)
		}
		slog.Info("updated hostname", "hostname", userData.Hostname)
	}

	if userData.User != "" && userData.Password != "" {
		if err := system.UpdatePassword(userData.User, userData.Password); err != nil {
			slog.Error("failed to update password", "user", userData.User, "error", err)
			os.Exit(1)
		}
		slog.Info("updated password", "user", userData.User)
	}

	if err := system.UpdateHostsFile(userData); err != nil {
		slog.Error("failed to update /etc/hosts", "error", err)
		os.Exit(1)
	}

	networkConfigPath := filepath.Join(mountDir, "network-config")
	networkConfigData, err := os.ReadFile(networkConfigPath)
	if err != nil && !os.IsNotExist(err) {
		slog.Error("failed to read network-config", "path", networkConfigPath, "error", err)
		os.Exit(1)
	}
	if err == nil {
		slog.Info("read network-config", "path", networkConfigPath)

		var networkConfig types.NetworkConfig
		if err := types.UnmarshalNetworkConfig(networkConfigData, &networkConfig, *strictFlag); err != nil {
			slog.Error("failed to parse network-config", "error", err)
			os.Exit(1)
		}
		slog.Debug("parsed network-config", "config", networkConfig)

		if err := network.GenerateSystemdNetworkConfig(networkConfig); err != nil {
			slog.Error("failed to generate systemd-networkd config", "error", err)
			os.Exit(1)
		}
	} else {
		slog.Info("no network-config found, skipping", "path", networkConfigPath)
	}

	if err := system.CheckAndGenerateSSHKeys(); err != nil {
		slog.Error("failed to check/generate SSH keys", "error", err)
		os.Exit(1)
	}

	slog.Info("completed successfully")
}
