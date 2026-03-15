package system

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
	"no-cloud/internal/types"
)

const sshKeyPath = "/etc/ssh/ssh_host_rsa_key"

func IsValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
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
	cmd := exec.Command("usermod", "-p", hashedPassword, user)
	return cmd.Run()
}

func UpdateHostsFile(userData types.UserData) error {
	return updateHostsFileAt("/etc/hosts", userData)
}

func updateHostsFileAt(hostsPath string, userData types.UserData) error {
	if !userData.ManageEtcHosts {
		return nil
	}

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
