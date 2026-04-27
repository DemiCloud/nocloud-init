package system

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/demicloud/nocloud-init/internal/types"
)

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"myhost", true},
		{"my-host", true},
		{"my.host.example.com", true},
		{"host123", true},
		{"123host", true},
		{"a", true},
		// uppercase letters are permitted (RFC 952 is case-insensitive)
		{"MyHost", true},
		{"MyHost123.Example.COM", true},
		// invalid
		{"", false},
		{"host_name", false},
		{"host name", false},
		{"host!", false},
		{"host@example.com", false},
		{strings.Repeat("a", 253), false}, // single label of 253 chars exceeds 63-char label limit
		{strings.Repeat("a", 254), false},
		// total length boundary: 63+1+63+1+63+1+61 = 253 (valid), +1 label char = 254 (invalid)
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
		// label starts/ends with hyphen (RFC 952)
		{"-host", false},
		{"host-", false},
		{"my.-host.com", false},
		{"my.host-.com", false},
		// label too long (RFC 1035 §2.3.4)
		{strings.Repeat("a", 63) + ".com", true},
		{strings.Repeat("a", 64) + ".com", false},
		// empty label (double dot)
		{"host..example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsValidHostname(tt.input)
			if got != tt.want {
				t.Errorf("IsValidHostname(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsValidHashedPassword(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// valid crypt(3) hashes
		{"$6$rounds=5000$salt$longhash", true},        // SHA-512
		{"$5$salt$hash", true},                        // SHA-256
		{"$y$j9T$salt$hash", true},                    // yescrypt
		{"$2b$12$saltandhash", true},                  // bcrypt
		{"$1$salt$hash", true},                        // MD5 (legacy)
		// invalid: plaintext
		{"password", false},
		{"", false},
		{"$", false},
		{"$$hash", false},  // empty ID
		{"$ $hash", false}, // space in ID
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsValidHashedPassword(tt.input)
			if got != tt.want {
				t.Errorf("IsValidHashedPassword(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestUpdateHostsFile(t *testing.T) {
	tests := []struct {
		name          string
		initialHosts  string
		userData      types.UserData
		wantContains  []string
		wantAbsent    []string
	}{
		{
			name: "adds loopback entry when manage_etc_hosts is true",
			initialHosts: `127.0.0.1 localhost
::1 localhost ip6-localhost
`,
			userData: types.UserData{
				ManageEtcHosts: true,
				Hostname:       "myhost",
				FQDN:           "myhost.example.com",
			},
			wantContains: []string{"127.0.1.1 myhost.example.com myhost", "127.0.0.1 localhost"},
		},
		{
			name: "replaces existing 127.0.1.1 entry",
			initialHosts: `127.0.1.1 oldhost.example.com oldhost
127.0.0.1 localhost
`,
			userData: types.UserData{
				ManageEtcHosts: true,
				Hostname:       "newhost",
				FQDN:           "newhost.example.com",
			},
			wantContains: []string{"127.0.1.1 newhost.example.com newhost", "127.0.0.1 localhost"},
			wantAbsent:   []string{"oldhost"},
		},
		{
			name: "no-op when manage_etc_hosts is false",
			initialHosts: `127.0.0.1 localhost
`,
			userData: types.UserData{
				ManageEtcHosts: false,
				Hostname:       "myhost",
				FQDN:           "myhost.example.com",
			},
			wantContains: []string{"127.0.0.1 localhost"},
			wantAbsent:   []string{"127.0.1.1"},
		},
		{
			name: "empty FQDN produces single-space entry",
			initialHosts: `127.0.0.1 localhost
`,
			userData: types.UserData{
				ManageEtcHosts: true,
				Hostname:       "myhost",
				FQDN:           "",
			},
			wantContains: []string{"127.0.1.1 myhost"},
			wantAbsent:   []string{"127.0.1.1  myhost"},
		},
		{
			name: "no-op when manage_etc_hosts is true but hostname is empty",
			initialHosts: `127.0.0.1 localhost
`,
			userData: types.UserData{
				ManageEtcHosts: true,
				Hostname:       "",
				FQDN:           "",
			},
			wantContains: []string{"127.0.0.1 localhost"},
			wantAbsent:   []string{"127.0.1.1"},
		},
		{
			// Multiple pre-existing 127.0.1.1 lines must all be removed and
			// replaced with exactly one correct entry.
			name: "removes all existing 127.0.1.1 entries",
			initialHosts: `127.0.1.1 oldhost1
127.0.1.1 oldhost2.example.com oldhost2
127.0.0.1 localhost
`,
			userData: types.UserData{
				ManageEtcHosts: true,
				Hostname:       "newhost",
				FQDN:           "newhost.example.com",
			},
			wantContains: []string{"127.0.1.1 newhost.example.com newhost", "127.0.0.1 localhost"},
			wantAbsent:   []string{"oldhost1", "oldhost2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "hosts")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			if _, err := f.WriteString(tt.initialHosts); err != nil {
				t.Fatalf("failed to write initial hosts: %v", err)
			}
			f.Close()

			if err := updateHostsFileAt(f.Name(), tt.userData); err != nil {
				t.Fatalf("updateHostsFileAt() error = %v", err)
			}

			content, err := os.ReadFile(f.Name())
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}
			result := string(content)

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("result missing %q\ngot:\n%s", want, result)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(result, absent) {
					t.Errorf("result should not contain %q\ngot:\n%s", absent, result)
				}
			}
		})
	}
}

func TestUpdatePasswordCredentialFormat(t *testing.T) {
	user := "alice"
	hash := "$6$rounds=5000$salt$longhash"

	outFile := filepath.Join(t.TempDir(), "stdin-capture")
	cmd := exec.Command("tee", outFile)
	if err := updatePasswordCmd(cmd, user, hash); err != nil {
		t.Fatalf("updatePasswordCmd: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	want := user + ":" + hash + "\n"
	if string(got) != want {
		t.Errorf("stdin content = %q, want %q", string(got), want)
	}

	// Verify the hash is not exposed in command arguments.
	for _, arg := range cmd.Args {
		if arg == hash {
			t.Errorf("hash found in command arguments: %v", cmd.Args)
		}
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostname")
	data := []byte("myhost\n")

	if err := writeFileAtomic(path, data, 0644); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", string(got), string(data))
	}

	// No leftover temp files must remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "hostname" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}

	// Permissions must match what was requested.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("file permissions = %o, want 0644", info.Mode().Perm())
	}
}

// TestUpdateHostsFileAt_MissingFile verifies that updateHostsFileAt returns an
// error when the target hosts file does not exist, rather than creating it
// silently (preserving the invariant that /etc/hosts must already be present).
func TestUpdateHostsFileAt_MissingFile(t *testing.T) {
	ud := types.UserData{ManageEtcHosts: true, Hostname: "myhost"}
	err := updateHostsFileAt(filepath.Join(t.TempDir(), "nonexistent-hosts"), ud)
	if err == nil {
		t.Fatal("expected error for nonexistent hosts file, got nil")
	}
}

// TestUpdateHostsFile_Permissions verifies that updateHostsFileAt writes the
// resulting /etc/hosts with mode 0644 so non-root processes can read it.
func TestUpdateHostsFile_Permissions(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hosts")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString("127.0.0.1 localhost\n"); err != nil {
		t.Fatalf("failed to write initial hosts: %v", err)
	}
	f.Close()

	ud := types.UserData{ManageEtcHosts: true, Hostname: "myhost"}
	if err := updateHostsFileAt(f.Name(), ud); err != nil {
		t.Fatalf("updateHostsFileAt() error = %v", err)
	}

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Errorf("hosts file permissions = %04o, want 0644", got)
	}
}

func TestWriteAuthorizedKeysAt(t *testing.T) {
	const key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-key-1 user@host"
	const key2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test-key-2 user@host"

	tests := []struct {
		name         string
		initialFile  string // "" means file doesn't exist yet
		keys         []string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:        "new file created with block",
			initialFile: "",
			keys:        []string{key1},
			wantContains: []string{
				"# BEGIN nocloud-init managed keys",
				key1,
				"# END nocloud-init managed keys",
			},
		},
		{
			name:        "existing file without block gets block appended",
			initialFile: "ssh-rsa AAAA pre-existing-key user@host\n",
			keys:        []string{key1},
			wantContains: []string{
				"pre-existing-key",
				"# BEGIN nocloud-init managed keys",
				key1,
				"# END nocloud-init managed keys",
			},
		},
		{
			name:        "existing file without trailing newline gets separator before block",
			initialFile: "ssh-rsa AAAA pre-existing-key user@host",
			keys:        []string{key1},
			wantContains: []string{
				"pre-existing-key",
				"# BEGIN nocloud-init managed keys",
				key1,
				"# END nocloud-init managed keys",
			},
		},
		{
			name:        "existing block is replaced, not duplicated",
			initialFile: "# BEGIN nocloud-init managed keys\n" + key2 + "\n# END nocloud-init managed keys\n",
			keys:        []string{key1},
			wantContains: []string{
				"# BEGIN nocloud-init managed keys",
				key1,
				"# END nocloud-init managed keys",
			},
			wantAbsent: []string{key2},
		},
		{
			name: "block in middle of file: surrounding keys preserved",
			initialFile: "ssh-rsa AAAA before user@host\n" +
				"# BEGIN nocloud-init managed keys\n" + key2 + "\n# END nocloud-init managed keys\n" +
				"ssh-rsa AAAA after user@host\n",
			keys: []string{key1},
			wantContains: []string{
				"before",
				"# BEGIN nocloud-init managed keys",
				key1,
				"# END nocloud-init managed keys",
				"after",
			},
			wantAbsent: []string{key2},
		},
		{
			name:        "multiple keys written",
			initialFile: "",
			keys:        []string{key1, key2},
			wantContains: []string{
				"# BEGIN nocloud-init managed keys",
				key1,
				key2,
				"# END nocloud-init managed keys",
			},
		},
		{
			name:        "invalid entries are skipped",
			initialFile: "",
			keys:        []string{"", key1, "ssh-rsa bad\x00key", "ssh-rsa with\nnewline"},
			wantContains: []string{
				key1,
				"# BEGIN nocloud-init managed keys",
				"# END nocloud-init managed keys",
			},
			wantAbsent: []string{"bad\x00key", "with\nnewline"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sshDir := filepath.Join(dir, ".ssh")
			akPath := filepath.Join(sshDir, "authorized_keys")

			if tt.initialFile != "" {
				if err := os.MkdirAll(sshDir, 0700); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.WriteFile(akPath, []byte(tt.initialFile), 0600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}

			if err := writeAuthorizedKeysAt(sshDir, akPath, tt.keys); err != nil {
				t.Fatalf("writeAuthorizedKeysAt() error = %v", err)
			}

			content, err := os.ReadFile(akPath)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			result := string(content)

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("result missing %q\ngot:\n%s", want, result)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(result, absent) {
					t.Errorf("result should not contain %q\ngot:\n%s", absent, result)
				}
			}
		})
	}
}

func TestWriteAuthorizedKeysAt_Permissions(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	akPath := filepath.Join(sshDir, "authorized_keys")

	if err := writeAuthorizedKeysAt(sshDir, akPath, []string{"ssh-ed25519 AAAA key"}); err != nil {
		t.Fatalf("writeAuthorizedKeysAt() error = %v", err)
	}

	// .ssh directory must be 0700
	sshInfo, err := os.Stat(sshDir)
	if err != nil {
		t.Fatalf("Stat .ssh: %v", err)
	}
	if got := sshInfo.Mode().Perm(); got != 0700 {
		t.Errorf(".ssh permissions = %04o, want 0700", got)
	}

	// authorized_keys must be 0600
	akInfo, err := os.Stat(akPath)
	if err != nil {
		t.Fatalf("Stat authorized_keys: %v", err)
	}
	if got := akInfo.Mode().Perm(); got != 0600 {
		t.Errorf("authorized_keys permissions = %04o, want 0600", got)
	}
}

func TestIsValidWritePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/myapp/config.cfg", true},
		{"/tmp/test.txt", true},
		{"/var/lib/data/file.json", true},
		{"/usr/local/bin/myscript", true},
		// invalid
		{"", false},
		{"/", false},
		{"relative/path", false},
		{"relative", false},
		{"./relative", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isValidWritePath(tt.path); got != tt.want {
				t.Errorf("isValidWritePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDecodeWriteFileContent(t *testing.T) {
	// Build a gzip+base64 payload for the combo encoding tests.
	var gzBuf bytes.Buffer
	w := gzip.NewWriter(&gzBuf)
	_, _ = w.Write([]byte("hello gzip"))
	_ = w.Close()
	gzB64 := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

	tests := []struct {
		name     string
		content  string
		encoding string
		want     string
		wantErr  bool
	}{
		{
			name:     "empty encoding is plain text",
			content:  "hello world",
			encoding: "",
			want:     "hello world",
		},
		{
			name:     "text/plain explicit",
			content:  "hello world",
			encoding: "text/plain",
			want:     "hello world",
		},
		{
			name:     "b64 encoding",
			content:  base64.StdEncoding.EncodeToString([]byte("hello world")),
			encoding: "b64",
			want:     "hello world",
		},
		{
			name:     "base64 encoding",
			content:  base64.StdEncoding.EncodeToString([]byte("hello world")),
			encoding: "base64",
			want:     "hello world",
		},
		{
			name:     "base64 with embedded whitespace",
			content:  "aGVs\nbG8g\nd29y\nbGQ=",
			encoding: "b64",
			want:     "hello world",
		},
		{
			name:     "encoding name is case-insensitive",
			content:  base64.StdEncoding.EncodeToString([]byte("hello world")),
			encoding: "Base64",
			want:     "hello world",
		},
		{
			name:     "gz+b64 encoding",
			content:  gzB64,
			encoding: "gz+b64",
			want:     "hello gzip",
		},
		{
			name:     "gz+base64 encoding",
			content:  gzB64,
			encoding: "gz+base64",
			want:     "hello gzip",
		},
		{
			name:     "gzip+b64 encoding",
			content:  gzB64,
			encoding: "gzip+b64",
			want:     "hello gzip",
		},
		{
			name:     "gzip+base64 encoding",
			content:  gzB64,
			encoding: "gzip+base64",
			want:     "hello gzip",
		},
		{
			name:     "invalid base64 returns error",
			content:  "not-valid-base64!!!",
			encoding: "b64",
			wantErr:  true,
		},
		{
			name:     "unsupported encoding returns error",
			content:  "",
			encoding: "bz2",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeWriteFileContent(tt.content, tt.encoding)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeWriteFileContent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestIsValidNTPServer(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0.pool.ntp.org", true},
		{"ntp.example.com", true},
		{"192.168.1.1", true},
		{"2001:db8::1", true},
		{strings.Repeat("a", 253), true},
		// invalid
		{"", false},
		{"ntp server", false}, // space
		{"ntp\tserver", false}, // tab
		{"ntp\nserver", false}, // newline
		{"ntp\x00server", false}, // null byte
		{strings.Repeat("a", 254), false}, // too long
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidNTPServer(tt.input); got != tt.want {
				t.Errorf("isValidNTPServer(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseChronyConfdir(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{
			name:    "confdir present",
			content: "pool pool.ntp.org iburst\nconfdir /etc/chrony/conf.d\nrtcsync\n",
			want:    "/etc/chrony/conf.d",
		},
		{
			name:    "confdir with tab",
			content: "confdir\t/etc/chrony/conf.d\n",
			want:    "/etc/chrony/conf.d",
		},
		{
			name:    "confdir first match wins",
			content: "confdir /first\nconfdir /second\n",
			want:    "/first",
		},
		{
			name:    "no confdir",
			content: "pool pool.ntp.org iburst\nrtcsync\n",
			want:    "",
		},
		{
			name:    "confdir keyword in comment ignored",
			content: "# confdir /commented\npool pool.ntp.org iburst\n",
			want:    "",
		},
		{
			name:    "empty file",
			content: "",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "chrony.conf.*")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tt.content); err != nil {
				t.Fatal(err)
			}
			f.Close()

			got, err := parseChronyConfdir(f.Name())
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseChronyConfdir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseChronyConfdir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyNTP(t *testing.T) {
	t.Run("empty servers is no-op", func(t *testing.T) {
		dir := t.TempDir()
		if err := applyNTPAt(nil, nil, dir); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Errorf("expected no files written, got %v", entries)
		}
	})

	t.Run("invalid server returns error", func(t *testing.T) {
		dir := t.TempDir()
		err := applyNTPAt([]string{"bad server"}, nil, dir)
		if err == nil {
			t.Fatal("expected error for server with space, got nil")
		}
	})

	t.Run("chrony with confdir writes drop-in", func(t *testing.T) {
		tmp := t.TempDir()
		confdir := filepath.Join(tmp, "conf.d")

		chronyConf := filepath.Join(tmp, "chrony.conf")
		if err := os.WriteFile(chronyConf, []byte("pool pool.ntp.org iburst\nconfdir "+confdir+"\nrtcsync\n"), 0644); err != nil {
			t.Fatal(err)
		}

		timesyncdDir := filepath.Join(tmp, "timesyncd.conf.d")
		servers := []string{"0.pool.ntp.org", "1.pool.ntp.org"}
		if err := applyNTPAt(servers, []string{chronyConf}, timesyncdDir); err != nil {
			t.Fatal(err)
		}

		// chrony drop-in must exist
		dropIn := filepath.Join(confdir, "nocloud-init.conf")
		data, err := os.ReadFile(dropIn)
		if err != nil {
			t.Fatalf("chrony drop-in not written: %v", err)
		}
		content := string(data)
		for _, s := range servers {
			want := "server " + s + " iburst"
			if !strings.Contains(content, want) {
				t.Errorf("drop-in missing %q; got:\n%s", want, content)
			}
		}

		// timesyncd drop-in must NOT exist
		if _, err := os.Stat(filepath.Join(timesyncdDir, "nocloud-init.conf")); !os.IsNotExist(err) {
			t.Error("timesyncd drop-in should not have been written when chrony was used")
		}
	})

	t.Run("chrony without confdir falls through to timesyncd", func(t *testing.T) {
		tmp := t.TempDir()

		chronyConf := filepath.Join(tmp, "chrony.conf")
		if err := os.WriteFile(chronyConf, []byte("pool pool.ntp.org iburst\nrtcsync\n"), 0644); err != nil {
			t.Fatal(err)
		}

		timesyncdDir := filepath.Join(tmp, "timesyncd.conf.d")
		servers := []string{"time.cloudflare.com"}
		if err := applyNTPAt(servers, []string{chronyConf}, timesyncdDir); err != nil {
			t.Fatal(err)
		}

		dropIn := filepath.Join(timesyncdDir, "nocloud-init.conf")
		data, err := os.ReadFile(dropIn)
		if err != nil {
			t.Fatalf("timesyncd drop-in not written: %v", err)
		}
		if !strings.Contains(string(data), "NTP=time.cloudflare.com") {
			t.Errorf("unexpected timesyncd content:\n%s", data)
		}
	})

	t.Run("no chrony config falls through to timesyncd", func(t *testing.T) {
		tmp := t.TempDir()
		timesyncdDir := filepath.Join(tmp, "timesyncd.conf.d")
		servers := []string{"0.pool.ntp.org", "1.pool.ntp.org"}

		if err := applyNTPAt(servers, []string{filepath.Join(tmp, "nonexistent.conf")}, timesyncdDir); err != nil {
			t.Fatal(err)
		}

		dropIn := filepath.Join(timesyncdDir, "nocloud-init.conf")
		data, err := os.ReadFile(dropIn)
		if err != nil {
			t.Fatalf("timesyncd drop-in not written: %v", err)
		}
		content := string(data)
		if !strings.Contains(content, "[Time]") {
			t.Errorf("missing [Time] section; got:\n%s", content)
		}
		if !strings.Contains(content, "NTP=0.pool.ntp.org 1.pool.ntp.org") {
			t.Errorf("unexpected NTP= line; got:\n%s", content)
		}
	})

	t.Run("timesyncd drop-in is overwritten on re-run", func(t *testing.T) {
		tmp := t.TempDir()
		timesyncdDir := filepath.Join(tmp, "timesyncd.conf.d")

		first := []string{"old.ntp.example.com"}
		if err := applyNTPAt(first, nil, timesyncdDir); err != nil {
			t.Fatal(err)
		}

		second := []string{"new.ntp.example.com"}
		if err := applyNTPAt(second, nil, timesyncdDir); err != nil {
			t.Fatal(err)
		}

		data, _ := os.ReadFile(filepath.Join(timesyncdDir, "nocloud-init.conf"))
		if strings.Contains(string(data), "old.ntp.example.com") {
			t.Error("old NTP server still present after second run")
		}
		if !strings.Contains(string(data), "new.ntp.example.com") {
			t.Error("new NTP server missing after second run")
		}
	})
}

func TestParseFilePermissions(t *testing.T) {
	tests := []struct {
		input   string
		want    os.FileMode
		wantErr bool
	}{
		{"", 0644, false},
		{"0644", 0644, false},
		{"644", 0644, false},
		{"0755", 0755, false},
		{"0600", 0600, false},
		{"0777", 0777, false},
		{"777", 0777, false},
		{"not-octal", 0, true},
		{"9999", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseFilePermissions(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseFilePermissions(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("parseFilePermissions(%q) = %04o, want %04o", tt.input, got, tt.want)
			}
		})
	}
}

func TestWriteFiles(t *testing.T) {
	tests := []struct {
		name        string
		files       []types.WriteFile
		wantContent map[string]string   // relative path → expected content
		wantPerm    map[string]os.FileMode
		wantErr     bool
	}{
		{
			name: "plain text file",
			files: []types.WriteFile{
				{Path: "/config/test.txt", Content: "hello world"},
			},
			wantContent: map[string]string{"/config/test.txt": "hello world"},
		},
		{
			name: "base64 encoded content",
			files: []types.WriteFile{
				{Path: "/config/test.txt", Content: base64.StdEncoding.EncodeToString([]byte("hello world")), Encoding: "b64"},
			},
			wantContent: map[string]string{"/config/test.txt": "hello world"},
		},
		{
			name: "custom permissions",
			files: []types.WriteFile{
				{Path: "/config/exec.sh", Content: "#!/bin/sh\n", Permissions: "0755"},
			},
			wantContent: map[string]string{"/config/exec.sh": "#!/bin/sh\n"},
			wantPerm:    map[string]os.FileMode{"/config/exec.sh": 0755},
		},
		{
			name: "default permissions are 0644",
			files: []types.WriteFile{
				{Path: "/config/default.txt", Content: "data"},
			},
			wantPerm: map[string]os.FileMode{"/config/default.txt": 0644},
		},
		{
			name: "creates parent directories",
			files: []types.WriteFile{
				{Path: "/a/b/c/deep.txt", Content: "deep"},
			},
			wantContent: map[string]string{"/a/b/c/deep.txt": "deep"},
		},
		{
			name: "multiple files",
			files: []types.WriteFile{
				{Path: "/etc/a.conf", Content: "a"},
				{Path: "/etc/b.conf", Content: "b"},
			},
			wantContent: map[string]string{"/etc/a.conf": "a", "/etc/b.conf": "b"},
		},
		{
			name: "overwrites existing file",
			files: []types.WriteFile{
				{Path: "/config/existing.txt", Content: "new content"},
			},
			wantContent: map[string]string{"/config/existing.txt": "new content"},
		},
		{
			name:    "relative path is rejected",
			files:   []types.WriteFile{{Path: "relative/path.txt", Content: "x"}},
			wantErr: true,
		},
		{
			name:    "empty path is rejected",
			files:   []types.WriteFile{{Path: "", Content: "x"}},
			wantErr: true,
		},
		{
			name:    "root path is rejected",
			files:   []types.WriteFile{{Path: "/", Content: "x"}},
			wantErr: true,
		},
		{
			name:    "invalid encoding returns error",
			files:   []types.WriteFile{{Path: "/config/test.txt", Content: "data", Encoding: "bz2"}},
			wantErr: true,
		},
		{
			name:    "invalid permissions return error",
			files:   []types.WriteFile{{Path: "/config/test.txt", Content: "data", Permissions: "not-octal"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()

			// Rewrite absolute paths to be under the temp root so tests don't
			// touch the real filesystem.
			files := make([]types.WriteFile, len(tt.files))
			copy(files, tt.files)
			for i := range files {
				if filepath.IsAbs(files[i].Path) {
					files[i].Path = filepath.Join(root, files[i].Path)
				}
			}

			// Pre-create a file for the "overwrites existing" case.
			if tt.name == "overwrites existing file" {
				p := filepath.Join(root, "/config/existing.txt")
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				if err := os.WriteFile(p, []byte("old content"), 0644); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}

			err := WriteFiles(files)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WriteFiles() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			for rel, wantContent := range tt.wantContent {
				p := filepath.Join(root, rel)
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("ReadFile(%s): %v", p, err)
				}
				if string(got) != wantContent {
					t.Errorf("content of %s = %q, want %q", rel, string(got), wantContent)
				}
			}
			for rel, wantMode := range tt.wantPerm {
				p := filepath.Join(root, rel)
				info, err := os.Stat(p)
				if err != nil {
					t.Fatalf("Stat(%s): %v", p, err)
				}
				if got := info.Mode().Perm(); got != wantMode {
					t.Errorf("perm of %s = %04o, want %04o", rel, got, wantMode)
				}
			}
		})
	}
}

func TestWriteFilesAppend(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "data.txt")

	// Write the initial file.
	if err := os.WriteFile(p, []byte("first\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	files := []types.WriteFile{{Path: p, Content: "second\n", Append: true}}
	if err := WriteFiles(files); err != nil {
		t.Fatalf("WriteFiles() error = %v", err)
	}

	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if want := "first\nsecond\n"; string(got) != want {
		t.Errorf("appended content = %q, want %q", string(got), want)
	}
}

func TestWriteFilesAppendCreatesFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "new.txt")

	files := []types.WriteFile{{Path: p, Content: "hello\n", Append: true}}
	if err := WriteFiles(files); err != nil {
		t.Fatalf("WriteFiles() error = %v", err)
	}

	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if want := "hello\n"; string(got) != want {
		t.Errorf("content = %q, want %q", string(got), want)
	}
}

func TestRunCmdShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")

	cmds := []types.RuncmdItem{
		{Shell: "echo hello > " + marker},
	}
	if err := RunCmd(cmds); err != nil {
		t.Fatalf("RunCmd() error = %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker file not created: %v", err)
	}
	if strings.TrimSpace(string(got)) != "hello" {
		t.Errorf("marker content = %q, want %q", strings.TrimSpace(string(got)), "hello")
	}
}

func TestRunCmdExec(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "exec-marker.txt")

	cmds := []types.RuncmdItem{
		{Args: []string{"touch", marker}},
	}
	if err := RunCmd(cmds); err != nil {
		t.Fatalf("RunCmd() error = %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker file not created: %v", err)
	}
}

func TestRunCmdFailure(t *testing.T) {
	cmds := []types.RuncmdItem{
		{Shell: "exit 42"},
	}
	if err := RunCmd(cmds); err == nil {
		t.Fatal("RunCmd() expected error for failing command, got nil")
	}
}

func TestRunCmdEmptyArgList(t *testing.T) {
	cmds := []types.RuncmdItem{
		{Args: []string{}},
	}
	if err := RunCmd(cmds); err == nil {
		t.Fatal("RunCmd() expected error for empty arg list, got nil")
	}
}

func TestRunCmdStopsOnFirstFailure(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "should-not-exist.txt")

	cmds := []types.RuncmdItem{
		{Shell: "exit 1"},
		{Args: []string{"touch", marker}},
	}
	if err := RunCmd(cmds); err == nil {
		t.Fatal("RunCmd() expected error, got nil")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("second command ran despite first failure")
	}
}

func TestIsValidLinuxName(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"sudo", true},
		{"docker", true},
		{"_internal", true},
		{"group-name", true},
		{"group.name", true},
		{"Group123", true},
		// too short / too long
		{"", false},
		{strings.Repeat("a", 33), false},
		// starts with digit or hyphen
		{"1group", false},
		{"-group", false},
		// contains invalid character
		{"my group", false},
		{"group@name", false},
		{"group/name", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidLinuxName(tt.input)
			if got != tt.want {
				t.Errorf("isValidLinuxName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCreateGroupsInvalidName(t *testing.T) {
	groups := types.GroupList{{Name: "bad name"}}
	if err := CreateGroups(groups); err == nil {
		t.Fatal("CreateGroups() expected error for invalid group name, got nil")
	}
}

func TestCreateGroupsInvalidMember(t *testing.T) {
	// groupadd --force will succeed for a real group name; but we can check
	// the member validation by mocking PATH so groupadd is a no-op.
	// Use a temp dir with a fake groupadd that exits 0.
	bin := t.TempDir()
	fakeGroupadd := filepath.Join(bin, "groupadd")
	if err := os.WriteFile(fakeGroupadd, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("writing fake groupadd: %v", err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	groups := types.GroupList{{Name: "mygroup", Members: []string{"bad user"}}}
	if err := CreateGroups(groups); err == nil {
		t.Fatal("CreateGroups() expected error for invalid member name, got nil")
	}
}

func TestCreateUsersSkipsDefault(t *testing.T) {
	// "default" entries must be skipped without executing any command.
	users := types.UserList{{Name: "default"}, {Name: ""}}
	// If any exec is attempted this test would fail in CI (no useradd available
	// without root). The fact that it returns nil proves nothing was exec'd.
	if err := CreateUsers(users); err != nil {
		t.Fatalf("CreateUsers() unexpected error: %v", err)
	}
}

func TestCreateUsersInvalidName(t *testing.T) {
	users := types.UserList{{Name: "bad user"}}
	if err := CreateUsers(users); err == nil {
		t.Fatal("CreateUsers() expected error for invalid user name, got nil")
	}
}

func TestCreateUsersInvalidShell(t *testing.T) {
	users := types.UserList{{Name: "alice", Shell: "bash"}} // not absolute
	if err := CreateUsers(users); err == nil {
		t.Fatal("CreateUsers() expected error for relative shell path, got nil")
	}
}

func TestCreateUsersInvalidGroupInList(t *testing.T) {
	users := types.UserList{{Name: "alice", Groups: types.UserGroupList{"bad group"}}}
	if err := CreateUsers(users); err == nil {
		t.Fatal("CreateUsers() expected error for invalid group name, got nil")
	}
}

func TestCreateUsersInvalidHashedPasswd(t *testing.T) {
	// A fake useradd so we reach the password step.
	bin := t.TempDir()
	fakeExe := filepath.Join(bin, "useradd")
	if err := os.WriteFile(fakeExe, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("writing fake useradd: %v", err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	users := types.UserList{{Name: "alice", HashedPasswd: "plaintext"}}
	if err := CreateUsers(users); err == nil {
		t.Fatal("CreateUsers() expected error for plaintext password, got nil")
	}
}

func TestIsValidTimezone(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"UTC", true},
		{"Europe/Berlin", true},
		{"America/New_York", true},
		{"Pacific/Auckland", true},
		{"Etc/GMT+5", true},
		// invalid
		{"", false},
		{"/UTC", false},               // absolute path
		{"../etc/passwd", false},      // traversal
		{"America//New_York", false},  // double slash → empty component
		{strings.Repeat("a", 65), false}, // too long
		{"UTC\x00evil", false},        // null byte
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidTimezone(tt.input)
			if got != tt.want {
				t.Errorf("isValidTimezone(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSetTimezoneAt_TiledatectlSuccess(t *testing.T) {
	bin := t.TempDir()
	// Fake timedatectl that exits 0 and records its arguments.
	argFile := filepath.Join(bin, "args.txt")
	fakeTiledatectl := filepath.Join(bin, "timedatectl")
	script := "#!/bin/sh\necho \"$@\" > " + argFile + "\nexit 0\n"
	if err := os.WriteFile(fakeTiledatectl, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	if err := setTimezoneAt("Europe/Berlin", dir, filepath.Join(dir, "localtime"), filepath.Join(dir, "timezone")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args, err := os.ReadFile(argFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "Europe/Berlin") {
		t.Errorf("timedatectl not called with correct zone; args = %q", string(args))
	}
}

func TestSetTimezoneAt_FallbackSymlink(t *testing.T) {
	// No timedatectl in PATH → fallback path.
	t.Setenv("PATH", t.TempDir())

	zoneinfoDir := t.TempDir()
	// Create a fake zoneinfo file for Europe/Berlin.
	zoneDir := filepath.Join(zoneinfoDir, "Europe")
	if err := os.MkdirAll(zoneDir, 0755); err != nil {
		t.Fatal(err)
	}
	zoneFile := filepath.Join(zoneDir, "Berlin")
	if err := os.WriteFile(zoneFile, []byte("fake zoneinfo"), 0644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	localtimePath := filepath.Join(dir, "localtime")
	etcTimezonePath := filepath.Join(dir, "timezone")

	if err := setTimezoneAt("Europe/Berlin", zoneinfoDir, localtimePath, etcTimezonePath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /etc/localtime must be a symlink pointing to the correct zoneinfo file.
	target, err := os.Readlink(localtimePath)
	if err != nil {
		t.Fatalf("expected localtime to be a symlink: %v", err)
	}
	if target != zoneFile {
		t.Errorf("symlink target = %q, want %q", target, zoneFile)
	}

	// /etc/timezone must contain the zone name.
	tz, err := os.ReadFile(etcTimezonePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(tz)) != "Europe/Berlin" {
		t.Errorf("/etc/timezone = %q, want %q", string(tz), "Europe/Berlin")
	}
}

func TestSetTimezoneAt_FallbackMissingZoneinfo(t *testing.T) {
	// No timedatectl in PATH.
	t.Setenv("PATH", t.TempDir())

	zoneinfoDir := t.TempDir() // empty — no zone files

	dir := t.TempDir()
	err := setTimezoneAt("Europe/Berlin", zoneinfoDir, filepath.Join(dir, "localtime"), filepath.Join(dir, "timezone"))
	if err == nil {
		t.Fatal("expected error for missing zoneinfo file, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q should mention \"not found\"", err.Error())
	}
}

func TestSetTimezoneAt_InvalidName(t *testing.T) {
	dir := t.TempDir()
	err := setTimezoneAt("../etc/passwd", dir, filepath.Join(dir, "localtime"), filepath.Join(dir, "timezone"))
	if err == nil {
		t.Fatal("expected error for invalid timezone name, got nil")
	}
}

func TestSetTimezoneAt_FallbackReplacesExisting(t *testing.T) {
	// No timedatectl in PATH.
	t.Setenv("PATH", t.TempDir())

	zoneinfoDir := t.TempDir()
	// Create two zones to simulate switching.
	for _, zone := range []string{"Europe/Berlin", "UTC"} {
		parts := strings.Split(zone, "/")
		if len(parts) == 2 {
			if err := os.MkdirAll(filepath.Join(zoneinfoDir, parts[0]), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(zoneinfoDir, filepath.FromSlash(zone)), []byte(zone), 0644); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	localtimePath := filepath.Join(dir, "localtime")
	etcTimezonePath := filepath.Join(dir, "timezone")

	// First call.
	if err := setTimezoneAt("Europe/Berlin", zoneinfoDir, localtimePath, etcTimezonePath); err != nil {
		t.Fatal(err)
	}
	// Second call should atomically replace the symlink.
	if err := setTimezoneAt("UTC", zoneinfoDir, localtimePath, etcTimezonePath); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	target, err := os.Readlink(localtimePath)
	if err != nil {
		t.Fatal(err)
	}
	wantTarget := filepath.Join(zoneinfoDir, "UTC")
	if target != wantTarget {
		t.Errorf("symlink target = %q, want %q", target, wantTarget)
	}
	tz, _ := os.ReadFile(etcTimezonePath)
	if strings.TrimSpace(string(tz)) != "UTC" {
		t.Errorf("/etc/timezone = %q, want %q", string(tz), "UTC")
	}
}

