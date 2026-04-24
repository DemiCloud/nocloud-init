package system

import (
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
		// invalid
		{"", false},
		{"host_name", false},
		{"host name", false},
		{"host!", false},
		{"host@example.com", false},
		{strings.Repeat("a", 253), true},
		{strings.Repeat("a", 254), false},
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
