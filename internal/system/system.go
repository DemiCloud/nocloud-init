package system

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
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

// IsValidHashedPassword reports whether s looks like a crypt(3) hashed
// password (i.e. has the form "$<id>$...").  It does not verify the hash
// itself — only that the value is not a bare plaintext string.
// All standard crypt(3) algorithms (SHA-512, SHA-256, yescrypt, bcrypt, …)
// begin with "$<alphanumeric-id>$".
func IsValidHashedPassword(s string) bool {
	if len(s) < 3 || s[0] != '$' {
		return false
	}
	rest := s[1:]
	end := strings.IndexByte(rest, '$')
	if end <= 0 {
		return false
	}
	id := rest[:end]
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
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
		return fmt.Errorf("failed to open %s: %w", hostsPath, err)
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
		return fmt.Errorf("error reading %s: %w", hostsPath, err)
	}

	// Prepend the correct entry
	lines = append([]string{loopbackEntry}, lines...)

	// Write to a temp file in the same directory so the rename is atomic
	// (same filesystem guaranteed).
	tmp, err := os.CreateTemp(filepath.Dir(hostsPath), ".hosts.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", hostsPath, err)
	}
	tmpName := tmp.Name()
	// Clean up the temp file on any failure path; after a successful rename
	// the path no longer exists so os.Remove is a harmless no-op.
	defer os.Remove(tmpName) //nolint:errcheck

	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod temp hosts file: %w", err)
	}

	writer := bufio.NewWriter(tmp)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	if err := writer.Flush(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp hosts file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp hosts file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp hosts file: %w", err)
	}
	if err := os.Rename(tmpName, hostsPath); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, hostsPath, err)
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to generate SSH host keys: %v: %s", err, out)
	}
	slog.Info("ensured SSH host keys are present")
	return nil
}

// authorizedKeys{Begin,End}Marker delimit the block of keys managed by
// nocloud-init inside an authorized_keys file.  Any pre-existing keys outside
// the block are preserved.  On every run the block content is replaced with
// the current set from user-data, making the operation idempotent.
const (
	authorizedKeysBeginMarker = "# BEGIN nocloud-init managed keys"
	authorizedKeysEndMarker   = "# END nocloud-init managed keys"
)

// WriteAuthorizedKeys installs keys into ~user/.ssh/authorized_keys.
// It looks up the user's home directory via the system passwd database.
// The .ssh directory is created with mode 0700 if absent; the
// authorized_keys file is written with mode 0600.
func WriteAuthorizedKeys(user string, keys []string) error {
	u, err := osuser.Lookup(user)
	if err != nil {
		return fmt.Errorf("failed to look up user %q: %w", user, err)
	}
	sshDir := filepath.Join(u.HomeDir, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")
	return writeAuthorizedKeysAt(sshDir, akPath, keys)
}

// writeAuthorizedKeysAt is the injectable inner function used directly by
// tests, keeping I/O out of the real filesystem.
func writeAuthorizedKeysAt(sshDir, akPath string, keys []string) error {
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory %s: %w", sshDir, err)
	}

	// Sanitize: strip whitespace and drop entries with embedded control
	// characters (newlines, null bytes) that would corrupt the file format.
	var sanitized []string
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || strings.ContainsAny(k, "\x00\r\n") {
			slog.Warn("skipping invalid ssh_authorized_keys entry")
			continue
		}
		sanitized = append(sanitized, k)
	}

	// Build the replacement block.
	blockLines := make([]string, 0, len(sanitized)+2)
	blockLines = append(blockLines, authorizedKeysBeginMarker)
	blockLines = append(blockLines, sanitized...)
	blockLines = append(blockLines, authorizedKeysEndMarker)
	newBlock := strings.Join(blockLines, "\n")

	// Read the existing file, if any.
	existing, err := os.ReadFile(akPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", akPath, err)
	}

	var output string
	if err == nil {
		content := string(existing)
		beginIdx := strings.Index(content, authorizedKeysBeginMarker)
		endIdx := strings.Index(content, authorizedKeysEndMarker)
		if beginIdx >= 0 && endIdx > beginIdx {
			// Replace the existing managed block in-place.
			output = content[:beginIdx] + newBlock + content[endIdx+len(authorizedKeysEndMarker):]
		} else {
			// Append a new block, ensuring a separating newline.
			if len(content) > 0 && !strings.HasSuffix(content, "\n") {
				content += "\n"
			}
			output = content + newBlock + "\n"
		}
	} else {
		// Brand-new file.
		output = newBlock + "\n"
	}

	if err := writeFileAtomic(akPath, []byte(output), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", akPath, err)
	}
	slog.Info("updated authorized_keys", "path", akPath, "keys", len(sanitized))
	return nil
}
