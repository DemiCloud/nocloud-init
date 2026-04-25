package main

import (
	"bytes"
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

// isCloudConfigFormat returns true if data begins with the "#cloud-config"
// header required by the cloud-config user-data format.  Other user-data
// formats (shell scripts starting with "#!", MIME multipart, etc.) are not
// supported and must be skipped rather than reported as a parse error.
func isCloudConfigFormat(data []byte) bool {
	// Strip optional UTF-8 BOM before inspecting the first line.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	return bytes.EqualFold(bytes.TrimRight(line, "\r "), []byte("#cloud-config"))
}

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
		fmt.Println("Checking required programs:")
		if err := service.CheckPrograms(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Checking required directories:")
		if err := service.CheckDirectories(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := service.InstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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

		trimmed := bytes.TrimSpace(userDataContent)
		if len(trimmed) > 0 && !isCloudConfigFormat(trimmed) {
			slog.Warn("user-data is not cloud-config format; only #cloud-config is supported — skipping")
		} else {
			if err := types.UnmarshalUserData(userDataContent, &userData, *strictFlag); err != nil {
				slog.Error("failed to parse user-data", "error", err)
				os.Exit(1)
			}
			safeUserData := userData
			if safeUserData.Password != "" {
				safeUserData.Password = "[REDACTED]"
			}
			slog.Debug("parsed user-data", "userData", safeUserData)
			if userData.Chpasswd.Expire {
				// chpasswd.expire is accepted for spec compatibility but not
				// implemented: forcing a password change on every boot would
				// lock out the user, which is the opposite of the intended effect
				// in a re-run-every-boot tool.
				slog.Debug("chpasswd.expire is set but not implemented; ignoring")
			}
		}
	} else {
		slog.Info("no user-data found, skipping", "path", userDataPath)
	}

	// Read meta-data for instance-id and fallback hostname.
	metaDataPath := filepath.Join(mountDir, "meta-data")
	var metaData types.MetaData
	metaDataContent, err := os.ReadFile(metaDataPath)
	if err != nil && !os.IsNotExist(err) {
		slog.Error("failed to read meta-data", "path", metaDataPath, "error", err)
		os.Exit(1)
	}
	if err == nil {
		slog.Info("read meta-data", "path", metaDataPath)
		if err := types.UnmarshalMetaData(metaDataContent, &metaData, *strictFlag); err != nil {
			slog.Error("failed to parse meta-data", "error", err)
			os.Exit(1)
		}
		if metaData.InstanceID == "" {
			// instance-id is required by the NoCloud spec for standard cloud-init,
			// where it gates first-boot detection.  nocloud-init is stateless and
			// re-runs every boot, so instance-id has no operational meaning here;
			// log at debug level only.
			slog.Debug("meta-data does not contain instance-id")
		}
		slog.Debug("parsed meta-data", "metaData", metaData)
	} else {
		slog.Info("no meta-data found, skipping", "path", metaDataPath)
	}

	// Resolve effective hostname: user-data takes precedence over meta-data.
	hostname := userData.Hostname
	if hostname == "" {
		if metaData.LocalHostname != "" {
			hostname = metaData.LocalHostname
			slog.Debug("using hostname from meta-data local-hostname", "hostname", hostname)
		} else if metaData.Hostname != "" {
			hostname = metaData.Hostname
			slog.Debug("using hostname from meta-data", "hostname", hostname)
		}
	}

	if hostname != "" && !system.IsValidHostname(hostname) {
		slog.Error("invalid hostname", "hostname", hostname)
		os.Exit(1)
	}
	if userData.FQDN != "" && !system.IsValidHostname(userData.FQDN) {
		slog.Error("invalid FQDN", "fqdn", userData.FQDN)
		os.Exit(1)
	}

	if hostname != "" {
		if err := system.UpdateHostname(hostname); err != nil {
			slog.Error("failed to update hostname", "error", err)
			os.Exit(1)
		}
		slog.Info("updated hostname", "hostname", hostname)
	}

	if userData.User != "" && userData.Password != "" {
		if !system.IsValidHashedPassword(userData.Password) {
			slog.Error("password must be a pre-hashed credential (e.g. $6$...); plaintext passwords are not supported")
			os.Exit(1)
		}
		if err := system.UpdatePassword(userData.User, userData.Password); err != nil {
			slog.Error("failed to update password", "user", userData.User, "error", err)
			os.Exit(1)
		}
		slog.Info("updated password", "user", userData.User)
	}

	// Pass effective hostname into hosts-file update so meta-data-sourced
	// hostnames are reflected there too.
	effectiveUserData := userData
	effectiveUserData.Hostname = hostname
	if err := system.UpdateHostsFile(effectiveUserData); err != nil {
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
