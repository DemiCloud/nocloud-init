package system

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
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

// isValidWritePath reports whether path is a safe absolute path for
// write_files.  The path must be absolute, non-empty, not "/", and must not
// contain null bytes.
func isValidWritePath(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	if !filepath.IsAbs(path) {
		return false
	}
	if strings.ContainsRune(path, 0) {
		return false
	}
	return true
}

// decodeWriteFileContent decodes content according to the encoding field of a
// write_files entry.  Supported encodings:
//
//	"" / "text/plain"           — returned as-is
//	"b64" / "base64"            — base64-decoded (whitespace stripped first)
//	"gz" / "gzip"               — gzip-decompressed
//	"gz+b64" / "gz+base64" / … — base64-decoded then gzip-decompressed
func decodeWriteFileContent(content, encoding string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))

	stripWS := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, s)
	}

	decodeB64 := func(s string) ([]byte, error) {
		data, err := base64.StdEncoding.DecodeString(stripWS(s))
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return data, nil
	}

	decompressGzip := func(data []byte) ([]byte, error) {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress: %w", err)
		}
		return out, nil
	}

	switch enc {
	case "", "text/plain":
		return []byte(content), nil
	case "b64", "base64":
		return decodeB64(content)
	case "gz", "gzip":
		return decompressGzip([]byte(content))
	case "gz+b64", "gz+base64", "gzip+b64", "gzip+base64":
		decoded, err := decodeB64(content)
		if err != nil {
			return nil, err
		}
		return decompressGzip(decoded)
	default:
		return nil, fmt.Errorf("unsupported encoding %q: supported values are empty (plain text), \"b64\", \"base64\", \"gz\", \"gzip\", \"gz+b64\", \"gz+base64\"", encoding)
	}
}

// parseFilePermissions parses an octal permission string (e.g. "0644" or
// "644").  An empty string returns the default permission 0644.
func parseFilePermissions(s string) (os.FileMode, error) {
	if s == "" {
		return 0644, nil
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid permissions %q: must be an octal string like \"0644\"", s)
	}
	return os.FileMode(n), nil
}

// setFileOwner changes the ownership of path to the user (and optionally
// group) specified in owner.  owner may be "user" or "user:group".
func setFileOwner(path, owner string) error {
	parts := strings.SplitN(owner, ":", 2)
	u, err := osuser.Lookup(parts[0])
	if err != nil {
		return fmt.Errorf("failed to look up owner user %q: %w", parts[0], err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid UID for user %q: %w", parts[0], err)
	}
	var gid int
	if len(parts) == 2 && parts[1] != "" {
		g, err := osuser.LookupGroup(parts[1])
		if err != nil {
			return fmt.Errorf("failed to look up owner group %q: %w", parts[1], err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("invalid GID for group %q: %w", parts[1], err)
		}
	} else {
		// Use the user's primary group.
		gid, err = strconv.Atoi(u.Gid)
		if err != nil {
			return fmt.Errorf("invalid primary GID for user %q: %w", parts[0], err)
		}
	}
	if err := unix.Lchown(path, uid, gid); err != nil {
		return fmt.Errorf("failed to chown %s to %s: %w", path, owner, err)
	}
	return nil
}

// WriteFiles processes all entries in the write_files cloud-config directive.
// Errors are returned on the first failure; files written before the failure
// are not rolled back.
func WriteFiles(files []types.WriteFile) error {
	for _, f := range files {
		if err := writeOneFile(f); err != nil {
			return fmt.Errorf("write_files: path %q: %w", f.Path, err)
		}
	}
	return nil
}

func writeOneFile(f types.WriteFile) error {
	path := filepath.Clean(f.Path)
	if !isValidWritePath(path) {
		return fmt.Errorf("invalid path %q: must be a non-root absolute path", f.Path)
	}

	data, err := decodeWriteFileContent(f.Content, f.Encoding)
	if err != nil {
		return fmt.Errorf("failed to decode content: %w", err)
	}

	perm, err := parseFilePermissions(f.Permissions)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directories for %s: %w", path, err)
	}

	if f.Append {
		fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
		if err != nil {
			return fmt.Errorf("failed to open %s for append: %w", path, err)
		}
		_, werr := fh.Write(data)
		cerr := fh.Close()
		if werr != nil {
			return fmt.Errorf("failed to write to %s: %w", path, werr)
		}
		if cerr != nil {
			return fmt.Errorf("failed to close %s: %w", path, cerr)
		}
	} else {
		if err := writeFileAtomic(path, data, perm); err != nil {
			return err
		}
	}

	if f.Owner != "" {
		if err := setFileOwner(path, f.Owner); err != nil {
			return err
		}
	}

	slog.Info("wrote file", "path", path)
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

// RunCmd executes each entry in the runcmd cloud-config list in order.
// String items are run via sh -c; list items are exec'd directly (no shell).
// Stdout and stderr are captured and logged at debug level.
// Execution stops and an error is returned on the first failure.
func RunCmd(cmds []types.RuncmdItem) error {
	for i, item := range cmds {
		if err := runOneCmd(item); err != nil {
			return fmt.Errorf("runcmd[%d]: %w", i, err)
		}
	}
	return nil
}

func runOneCmd(item types.RuncmdItem) error {
	var cmd *exec.Cmd
	if item.Shell != "" {
		cmd = exec.Command("sh", "-c", item.Shell)
	} else {
		if len(item.Args) == 0 {
			return fmt.Errorf("empty command list")
		}
		cmd = exec.Command(item.Args[0], item.Args[1:]...)
	}
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		slog.Debug("runcmd output", "cmd", cmdLabel(item), "output", strings.TrimRight(string(out), "\n"))
	}
	if err != nil {
		return fmt.Errorf("command %q failed: %w", cmdLabel(item), err)
	}
	slog.Info("runcmd executed", "cmd", cmdLabel(item))
	return nil
}

// cmdLabel returns a short human-readable label for a runcmd item for use in
// log messages and error strings.
func cmdLabel(item types.RuncmdItem) string {
	if item.Shell != "" {
		return item.Shell
	}
	return strings.Join(item.Args, " ")
}

// isValidLinuxName reports whether s is a valid Linux user or group name.
// Matches useradd(8) / groupadd(8) conventions: 1–32 characters, starts with
// a letter or underscore, followed by letters, digits, hyphens, underscores,
// or dots.
func isValidLinuxName(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i, c := range s {
		if i == 0 {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
				return false
			}
		} else {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

// CreateGroups creates each group listed in the groups cloud-config key.
// groupadd --force is used so an already-existing group is not an error.
// Members are added via usermod -aG after the group is created.
func CreateGroups(groups types.GroupList) error {
	for _, g := range groups {
		if err := createOneGroup(g); err != nil {
			return err
		}
	}
	return nil
}

func createOneGroup(g types.GroupEntry) error {
	if !isValidLinuxName(g.Name) {
		return fmt.Errorf("invalid group name %q", g.Name)
	}
	cmd := exec.Command("groupadd", "--force", g.Name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("groupadd %q: %w: %s", g.Name, err, strings.TrimSpace(string(out)))
	}
	slog.Info("created group", "group", g.Name)

	for _, user := range g.Members {
		if !isValidLinuxName(user) {
			return fmt.Errorf("invalid member name %q for group %q", user, g.Name)
		}
		cmd := exec.Command("usermod", "-aG", g.Name, user)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("usermod -aG %q %q: %w: %s", g.Name, user, err, strings.TrimSpace(string(out)))
		}
		slog.Info("added user to group", "user", user, "group", g.Name)
	}
	return nil
}

// CreateUsers creates each user entry in the users cloud-config list.
// Entries named "default" are silently skipped. If a user already exists
// (useradd exits with code 9), it is left in place and subsequent options
// (password, sudo, SSH keys) are still applied.
func CreateUsers(users types.UserList) error {
	for _, u := range users {
		if u.Name == "" || u.Name == "default" {
			continue
		}
		if err := createOneUser(u); err != nil {
			return err
		}
	}
	return nil
}

func createOneUser(u types.UserEntry) error {
	if !isValidLinuxName(u.Name) {
		return fmt.Errorf("invalid user name %q", u.Name)
	}

	args := []string{}
	if u.System {
		args = append(args, "--system")
	}
	if u.NoCreateHome {
		args = append(args, "--no-create-home")
	} else {
		args = append(args, "--create-home")
	}
	if u.Shell != "" {
		if !filepath.IsAbs(u.Shell) {
			return fmt.Errorf("user %q: shell %q must be an absolute path", u.Name, u.Shell)
		}
		args = append(args, "--shell", u.Shell)
	}
	if u.Gecos != "" {
		args = append(args, "--comment", u.Gecos)
	}
	if len(u.Groups) > 0 {
		for _, g := range u.Groups {
			if !isValidLinuxName(g) {
				return fmt.Errorf("user %q: invalid group name %q", u.Name, g)
			}
		}
		args = append(args, "--groups", strings.Join(u.Groups, ","))
	}
	args = append(args, u.Name)

	cmd := exec.Command("useradd", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 9 means the user already exists; leave them in place.
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 9 {
			slog.Debug("user already exists, skipping creation", "user", u.Name)
		} else {
			return fmt.Errorf("useradd %q: %w: %s", u.Name, err, strings.TrimSpace(string(out)))
		}
	} else {
		slog.Info("created user", "user", u.Name)
	}

	if u.HashedPasswd != "" {
		if !IsValidHashedPassword(u.HashedPasswd) {
			return fmt.Errorf("user %q: hashed_passwd must be a pre-hashed crypt(3) credential", u.Name)
		}
		if err := updatePasswordCmd(exec.Command("chpasswd", "-e"), u.Name, u.HashedPasswd); err != nil {
			return fmt.Errorf("user %q: failed to set password: %w", u.Name, err)
		}
	}

	if u.LockPasswd {
		cmd := exec.Command("passwd", "--lock", u.Name)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("user %q: passwd --lock: %w: %s", u.Name, err, strings.TrimSpace(string(out)))
		}
		slog.Info("locked password for user", "user", u.Name)
	}

	if u.Sudo != "" {
		// Write a sudoers drop-in. The filename is the validated user name so
		// it cannot contain path separators or other dangerous characters.
		sudoersPath := filepath.Join("/etc/sudoers.d", u.Name)
		content := u.Name + " " + u.Sudo + "\n"
		if err := writeFileAtomic(sudoersPath, []byte(content), 0440); err != nil {
			return fmt.Errorf("user %q: failed to write sudoers rule: %w", u.Name, err)
		}
		slog.Info("wrote sudoers rule", "user", u.Name, "path", sudoersPath)
	}

	if len(u.SSHAuthorizedKeys) > 0 {
		if err := WriteAuthorizedKeys(u.Name, u.SSHAuthorizedKeys); err != nil {
			return fmt.Errorf("user %q: failed to write authorized_keys: %w", u.Name, err)
		}
	}

	return nil
}

// isValidTimezone reports whether tz is a safe IANA timezone name.
// It must be non-empty, must not contain null bytes or consecutive dots that
// could escape the zoneinfo directory, and each component must be non-empty.
func isValidTimezone(tz string) bool {
	if tz == "" || len(tz) > 64 {
		return false
	}
	if strings.ContainsRune(tz, 0) {
		return false
	}
	// Check components on the raw string before any path cleaning so that
	// consecutive slashes (e.g. "America//New_York") are caught.
	for _, part := range strings.Split(tz, "/") {
		if part == "" || part == ".." || part == "." {
			return false
		}
	}
	// Reject any path traversal attempts after cleaning too.
	clean := filepath.Clean(tz)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return false
	}
	return true
}

// SetTimezone applies the IANA timezone name tz to the system.
//
// It tries the following in order:
//  1. timedatectl set-timezone <tz> — validates the zone, handles
//     /etc/localtime atomically, works on any modern systemd host.
//  2. Manual /etc/localtime symlink — used when timedatectl is absent
//     (minimal containers, early-boot environments). Validates that the
//     zoneinfo file exists before symlinking to prevent dangling links.
//     Also writes /etc/timezone for Debian/Ubuntu compatibility.
//
// If timedatectl is found but returns an error (e.g. invalid zone name) that
// error is returned immediately — the fallback is not attempted, because the
// zone name itself is the problem.
func SetTimezone(tz string) error {
	return setTimezoneAt(tz, "/usr/share/zoneinfo", "/etc/localtime", "/etc/timezone")
}

// setTimezoneAt is the injectable inner function used by tests.
func setTimezoneAt(tz, zoneinfoDir, localtimePath, etcTimezonePath string) error {
	if !isValidTimezone(tz) {
		return fmt.Errorf("invalid timezone %q: must be a non-empty IANA name (e.g. \"UTC\", \"Europe/Berlin\")", tz)
	}

	// Primary: timedatectl
	out, err := exec.Command("timedatectl", "set-timezone", tz).CombinedOutput()
	if err == nil {
		slog.Info("set timezone via timedatectl", "timezone", tz)
		return nil
	}

	// If timedatectl exists but failed, the zone name is likely invalid — don't
	// fall through.
	if !isNotFound(err) {
		return fmt.Errorf("timedatectl set-timezone %q failed: %w: %s", tz, err, strings.TrimSpace(string(out)))
	}

	// Fallback: manual symlink.
	slog.Debug("timedatectl not found, falling back to manual /etc/localtime symlink")

	zoneFile := filepath.Join(zoneinfoDir, filepath.FromSlash(tz))
	if _, err := os.Stat(zoneFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("timezone %q not found in %s", tz, zoneinfoDir)
		}
		return fmt.Errorf("failed to stat zoneinfo file for %q: %w", tz, err)
	}

	// Atomically replace /etc/localtime via temp symlink + rename.
	dir := filepath.Dir(localtimePath)
	tmp, err := os.CreateTemp(dir, ".localtime.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for localtime: %w", err)
	}
	tmpName := tmp.Name()
	tmp.Close()
	// Remove the placeholder file so we can create a symlink at that path.
	if err := os.Remove(tmpName); err != nil {
		return fmt.Errorf("failed to remove temp placeholder: %w", err)
	}
	defer os.Remove(tmpName) //nolint:errcheck

	if err := os.Symlink(zoneFile, tmpName); err != nil {
		return fmt.Errorf("failed to create temp symlink for localtime: %w", err)
	}
	if err := os.Rename(tmpName, localtimePath); err != nil {
		return fmt.Errorf("failed to rename localtime symlink: %w", err)
	}

	// Write /etc/timezone for Debian/Ubuntu compatibility (harmless elsewhere).
	_ = os.WriteFile(etcTimezonePath, []byte(tz+"\n"), 0644)

	slog.Info("set timezone via /etc/localtime symlink", "timezone", tz, "zoneFile", zoneFile)
	return nil
}

// isNotFound reports whether err (from exec.Command) indicates that the
// executable was not found in PATH.
func isNotFound(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false
	}
	return errors.Is(err, exec.ErrNotFound) || os.IsNotExist(err)
}

// isValidNTPServer reports whether s is a safe NTP server name (hostname or
// IP address).  It rejects empty strings, entries containing whitespace or
// ASCII control characters, and entries longer than 253 characters.
func isValidNTPServer(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if c <= 0x1f || c == 0x7f || c == ' ' {
			return false
		}
	}
	return true
}

// parseChronyConfdir reads the first "confdir <path>" directive from the
// chrony config file at configPath and returns the path.  Returns ("", nil)
// if the file contains no confdir directive.
func parseChronyConfdir(configPath string) (string, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Match "confdir" followed by at least one space or tab.
		if len(line) > 7 && strings.EqualFold(line[:7], "confdir") && (line[7] == ' ' || line[7] == '\t') {
			dir := strings.TrimSpace(line[7:])
			if dir != "" {
				return dir, nil
			}
		}
	}
	return "", scanner.Err()
}

var (
	// chronyConfigCandidates are the well-known locations for the chrony
	// configuration file, tried in order.
	chronyConfigCandidates = []string{
		"/etc/chrony/chrony.conf",
		"/etc/chrony.conf",
	}
	// timesyncdDropinDir is where systemd-timesyncd drop-in files are placed.
	timesyncdDropinDir = "/etc/systemd/timesyncd.conf.d"
)

// ApplyNTP configures NTP servers by probing for a supported daemon and
// writing a drop-in configuration file.  servers may contain hostnames or IP
// addresses; both are written identically.
//
// Probe order:
//  1. chrony — if a config file is found and declares a confdir, write a
//     "server <addr> iburst" drop-in there.
//  2. timesyncd — write an [Time]\nNTP= drop-in to
//     /etc/systemd/timesyncd.conf.d/.
//  3. If no daemon is detected, log a warning and return nil.
func ApplyNTP(servers []string) error {
	return applyNTPAt(servers, chronyConfigCandidates, timesyncdDropinDir)
}

// applyNTPAt is the injectable inner function used by tests.
func applyNTPAt(servers []string, chronyConfigs []string, timesyncdDir string) error {
	if len(servers) == 0 {
		return nil
	}
	for _, s := range servers {
		if !isValidNTPServer(s) {
			return fmt.Errorf("invalid NTP server %q: must be a non-empty hostname or IP address with no whitespace", s)
		}
	}

	// --- Probe chrony ---
	for _, cfgPath := range chronyConfigs {
		confdir, err := parseChronyConfdir(cfgPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to read chrony config %s: %w", cfgPath, err)
		}
		if confdir == "" {
			// Config exists but has no confdir directive.  Per design: log a
			// warning and skip rather than guessing a directory path; fall
			// through to timesyncd.
			slog.Warn("chrony config found but no confdir directive; skipping chrony NTP configuration — falling back to timesyncd", "config", cfgPath)
			break
		}

		// Write chrony drop-in.
		if err := os.MkdirAll(confdir, 0755); err != nil {
			return fmt.Errorf("failed to create chrony confdir %s: %w", confdir, err)
		}
		var buf strings.Builder
		for _, s := range servers {
			fmt.Fprintf(&buf, "server %s iburst\n", s)
		}
		dropIn := filepath.Join(confdir, "nocloud-init.conf")
		if err := writeFileAtomic(dropIn, []byte(buf.String()), 0644); err != nil {
			return fmt.Errorf("failed to write chrony drop-in %s: %w", dropIn, err)
		}
		slog.Info("configured NTP via chrony drop-in", "path", dropIn)
		return nil
	}

	// --- Fallback: systemd-timesyncd ---
	if err := os.MkdirAll(timesyncdDir, 0755); err != nil {
		slog.Warn("timesyncd drop-in directory unavailable; NTP configuration skipped", "dir", timesyncdDir, "error", err)
		return nil
	}
	content := "[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
	dropIn := filepath.Join(timesyncdDir, "nocloud-init.conf")
	if err := writeFileAtomic(dropIn, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write timesyncd drop-in %s: %w", dropIn, err)
	}
	slog.Info("configured NTP via timesyncd drop-in", "path", dropIn)
	return nil
}
