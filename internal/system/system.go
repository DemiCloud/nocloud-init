package system

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"github.com/demicloud/nocloud-init/internal/types"
)



func IsValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func UpdateHostname(hostname string) error {
	// 1. Write /etc/hostname atomically so a power failure can't leave a
	//    zero-length or partially-written file.
	if err := writeFileAtomic("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/hostname: %w", err)
	}

	// 2. Update kernel hostname directly.
	if err := unix.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("failed to set kernel hostname: %w", err)
	}

	// 3. Optional: pretty hostname (best-effort, non-critical).
	_ = os.WriteFile("/etc/machine-info", []byte("PRETTY_HOSTNAME="+hostname+"\n"), 0644)

	return nil
}

// writeFileAtomic writes data to path via a temp file + rename so that
// readers never observe a truncated file.  The temp file is created in the
// same directory as path to guarantee the rename is on the same filesystem.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// Remove the temp file on any failure; after a successful rename the path
	// no longer exists so os.Remove is a harmless no-op.
	defer os.Remove(tmpName) //nolint:errcheck

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod temp file for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp file for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp file for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

func UpdatePassword(user, hashedPassword string) error {
	return updatePasswordCmd(exec.Command("chpasswd", "-e"), user, hashedPassword)
}

func updatePasswordCmd(cmd *exec.Cmd, user, hashedPassword string) error {
	cmd.Stdin = strings.NewReader(user + ":" + hashedPassword + "\n")
	return cmd.Run()
}

func UpdateHostsFile(userData types.UserData) error {
	return updateHostsFileAt("/etc/hosts", userData)
}

func updateHostsFileAt(hostsPath string, userData types.UserData) error {
	if !userData.ManageEtcHosts {
		return nil
	}
	if userData.Hostname == "" {
		return nil
	}

	var loopbackEntry string
	if userData.FQDN != "" {
		loopbackEntry = fmt.Sprintf("127.0.1.1 %s %s", userData.FQDN, userData.Hostname)
	} else {
		loopbackEntry = fmt.Sprintf("127.0.1.1 %s", userData.Hostname)
	}

	file, err := os.Open(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", hostsPath, err)
	}

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
	file.Close()
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading %s: %v", hostsPath, err)
	}

	// Prepend the correct entry
	lines = append([]string{loopbackEntry}, lines...)

	// Write to a temp file in the same directory so the rename is atomic
	// (same filesystem guaranteed).
	tmp, err := os.CreateTemp(filepath.Dir(hostsPath), ".hosts.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %v", hostsPath, err)
	}
	tmpName := tmp.Name()
	// Clean up the temp file on any failure path; after a successful rename
	// the path no longer exists so os.Remove is a harmless no-op.
	defer os.Remove(tmpName) //nolint:errcheck

	writer := bufio.NewWriter(tmp)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	if err := writer.Flush(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp hosts file: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp hosts file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp hosts file: %v", err)
	}
	if err := os.Rename(tmpName, hostsPath); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %v", tmpName, hostsPath, err)
	}

	slog.Info("updated hosts file", "path", hostsPath)
	return nil
}

func CheckAndGenerateSSHKeys() error {
	// ssh-keygen -A generates any missing host key types and skips those that
	// already exist, making it safe to run unconditionally. Checking only one
	// key type (e.g. RSA) as a sentinel would miss newly-supported types
	// (e.g. Ed25519) that could be absent after an upgrade.
	cmd := exec.Command("ssh-keygen", "-A")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate SSH host keys: %v", err)
	}
	slog.Info("ensured SSH host keys are present")
	return nil
}
