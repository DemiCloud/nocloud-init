package system

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"github.com/demicloud/nocloud-init/internal/types"
)

const sshKeyPath = "/etc/ssh/ssh_host_rsa_key"

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
	// 1. Write /etc/hostname
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/hostname: %w", err)
	}

	// 2. Update kernel hostname directly
	if err := unix.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("failed to set kernel hostname: %w", err)
	}

	// 3. Optional: pretty hostname
	_ = os.WriteFile("/etc/machine-info", []byte("PRETTY_HOSTNAME="+hostname+"\n"), 0644)

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

	log.Printf("Updated %s with hostname entry", hostsPath)
	return nil
}

func CheckAndGenerateSSHKeys() error {
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
