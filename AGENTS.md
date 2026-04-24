# nocloud-init — Agent / Contributor Instructions

## Collaboration Philosophy

Development is a collaborative process. Agents are expected to exercise independent
technical judgment, not passive agreement. When a different solution better aligns with
industry standards or formal specifications (e.g., RFCs, systemd upstream docs,
cloud-init spec), agents should raise concerns and advocate for the more appropriate
approach.

## Project Overview

`nocloud-init` is a minimal cloud-init–compatible client implementing the NoCloud
datasource. It detects a CIDATA-labelled ISO 9660 device, mounts it, reads
`user-data` and `network-config`, and applies system configuration deterministically.

- Written in **Go 1.25**. Always **`CGO_ENABLED=0`**. **Linux only** (amd64, arm64).
- Produces a **single static binary** from `cmd/nocloud-init/`.
- Runs as **root** at boot, before `systemd-networkd` starts.
- Runs once per boot as a `oneshot` systemd service. If no CIDATA device is present,
  it exits cleanly without modifying the system.

Supported actions:
- Write systemd-networkd `.network` / `.link` files (NoCloud network-config v1 and v2)
- Update `/etc/resolv.conf` (skipped if it is a symlink, e.g. to systemd-resolved)
- Set hostname via `/etc/hostname` + `sethostname(2)`
- Update `/etc/hosts` loopback entry for FQDN resolution
- Update a user password via `usermod -p`
- Generate SSH host keys via `ssh-keygen` when missing

---

## Repository Layout

```text
cmd/
  nocloud-init/
    main.go         ← CLI flags (--help, --version, --install), orchestration logic
internal/
  mount/
    mount.go        ← CIDATA device discovery (/dev/disk/by-label), ISO mount/unmount
  network/
    network.go      ← systemd-networkd file generation; resolv.conf writer; v1+v2 support
    network_test.go
  service/
    service.go      ← ServiceName/Description constants; systemd unit install via dbus
  system/
    system.go       ← hostname, /etc/hosts, password, SSH key operations
    system_test.go
  types/
    types.go        ← UserData, NetworkConfig (v1+v2) structs; YAML/JSON unmarshaling
    types_test.go
    testdata/       ← YAML fixtures for unit tests
```

---

## Build Commands

```bash
# Development build → build/nocloud-init
make

# Run tests
make test          # equivalent: go test ./...

# Static analysis
make vet           # equivalent: go vet ./...

# Stripped, trimpath, multi-arch release tarballs → dist/
make release

# Remove build/ and dist/
make clean
```

**Never build into the repo root.** Always target `build/` explicitly or use `make`.
Compiled binaries belong only in `build/` or `dist/`, both of which are gitignored.

```bash
# Correct
make
go build -o build/nocloud-init ./cmd/nocloud-init/

# Wrong — drops binary in the working directory
go build ./cmd/nocloud-init/
```

---

## Git Workflow

**After every meaningful change, make a commit.** This applies to:

- Bug fixes (including single-line corrections)
- New features or behaviour changes
- Refactors or code reorganisation
- Documentation / AGENTS.md updates
- Build / Makefile changes

**Before committing, run the test suite and confirm it passes:**

```bash
make test && make vet
```

Do not commit if any test fails. If a change intentionally removes functionality,
update or delete the affected tests in the same commit. If you add new logic, add
corresponding tests before committing.

Do **not** push automatically; only commit locally unless the user explicitly asks
to push.

Follow the conventional-commits style used in the repo since v1.1.0:

- `feat:` — new user-visible feature
- `fix:` — bug fix
- `refactor:` — internal restructure, no behaviour change
- `docs:` — documentation only
- `build:` — Makefile, CI, or toolchain changes
- `chore:` — everything else (dependency updates, file renames, etc.)

---

## Key Conventions

### Go

- **Always `CGO_ENABLED=0`.** There are no exceptions. This tool is Linux-only and
  uses `golang.org/x/sys/unix` for all syscalls; no C libraries are needed.
- **Linux only.** Do not add Windows or macOS build tags or code paths.
- Version is injected at link time via `-ldflags "-X main.version=..."`.
  The variables `version`, `commit`, `date`, and `builtBy` live in `cmd/nocloud-init/main.go`.
- `internal/` packages must not import each other in a circular manner.
  `types` is the shared data layer; all other packages may import it.
  `service`, `network`, `system`, and `mount` are independent of each other.

### Testing

- Tests are pure unit tests — they must not require root, a real filesystem, or a
  running systemd. Use path arguments or `*_at` variants of internal functions
  (e.g. `updateResolvConfAt`, `updateHostsFileAt`) to keep I/O injectable.
- YAML fixtures go in `internal/types/testdata/`. Prefer adding a fixture file over
  embedding large multi-line strings in test code.
- The CI pipeline runs `go vet ./...` and `go test ./internal/...`. Both must pass
  before merging to `main`.

### Security

This binary runs as root on every boot. Apply extra scrutiny to any change that:

- Writes to `/etc/` or `/etc/systemd/network/`
- Calls external binaries (`usermod`, `ssh-keygen`)
- Parses untrusted user-data from the CIDATA ISO
- Touches mount/unmount logic

Validate all external inputs at the boundary (hostname format, address/netmask syntax,
MAC address strings). Never pass unsanitised strings from user-data directly to a
shell or `exec.Command`.
