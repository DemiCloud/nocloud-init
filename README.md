# nocloud-init

A minimal [NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html) datasource client. It detects a CIDATA-labelled ISO 9660 or vfat volume, mounts it, reads `user-data`, `meta-data`, and `network-config`, and applies system configuration deterministically on every boot. If no CIDATA device is present, it exits cleanly without modifying the system.

## Table of Contents

- [Supported Features](#supported-features)
- [Dependencies](#dependencies)
- [Compiling](#compiling)
  - [Using Make (recommended)](#using-make-recommended)
  - [Using Go directly](#using-go-directly)
- [Installation & Usage](#installation--usage)
  - [1. Install the binary](#1-install-the-binary)
  - [2. Install and enable the systemd service](#2-install-and-enable-the-systemd-service)
  - [3. Provide NoCloud seed data](#3-provide-nocloud-seed-data)
  - [CLI options](#cli-options)
- [Disabling](#disabling)
- [Wiki](#wiki)

## Supported Features

### Network configuration
- Static addressing
- DHCP
- Multiple interfaces
- Interface renaming (via `.link` files)
- Global DNS configuration
- systemd-networkd `.network` / `.link` file generation
- **Stale file cleanup**: on every run, previously-written `10-cloud-init-*` files are removed before new ones are written. This ensures that NICs removed from the hypervisor UI are not left behind in `/etc/systemd/network/`.

### System identity
- Hostname from `user-data` (takes precedence) or `meta-data` (`local-hostname` / `hostname` fallback)
- FQDN from `user-data.fqdn`; used as the primary name in the `/etc/hosts` loopback entry when set
- `/etc/hosts` loopback entry for proper FQDN resolution (e.g. `hostname -f`)

### User management
- Password update for a specified user (the field must contain a pre-hashed credential, e.g. `$6$…`; plaintext passwords are rejected)
- SSH host key generation when missing (safe for template cloning)

### Meta-data
- `instance-id`, `local-hostname`, and `hostname` fields are parsed from `meta-data`
- `instance-id` is informational only; it does not gate execution (see [Why nocloud-init](https://github.com/demicloud/nocloud-init/wiki/Why-nocloud-init))

## Dependencies
- `chpasswd` — for password updates (reads `user:hash` from stdin; the hash is never exposed in the process list)
- `ssh-keygen` — for SSH host key generation

### Network configuration
`nocloud-init` writes standard [systemd-networkd](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html) `.network` and `.link` files to `/etc/systemd/network/`. Any tool or service capable of consuming those files will work — `systemd-networkd` is the typical choice but is not a hard dependency.

## Compiling

Requires **Go 1.25** or later.

### Using Make (recommended)
Running `make` builds the binary into `build/nocloud-init`.

```
make          # development build → build/nocloud-init
make test     # run tests
make vet      # run go vet
make release  # stripped multi-arch tarballs → dist/
```

### Using Go directly
`go build -o build/nocloud-init ./cmd/nocloud-init/`

## Installation & Usage

### 1. Install the binary
Place the compiled binary anywhere on the system. It does **not** need to be in `PATH` because the installer generates a systemd service with the correct absolute `ExecStart` path.

Using Make (installs to `/usr/local/sbin/` by default; override with `PREFIX=` or `DESTDIR=`):

```
sudo make install
```

Or manually:

```
sudo install -m 0755 build/nocloud-init /usr/local/sbin/nocloud-init
```

### 2. Install and enable the systemd service
Run the installer to write the service unit and enable it:

```
sudo nocloud-init --install
sudo systemctl enable --now nocloud-init.service
```

### 3. Provide NoCloud seed data
Attach a CIDATA-labelled ISO 9660 or vfat volume containing any combination of:

- `user-data` (must begin with `#cloud-config`)
- `meta-data` (YAML; `instance-id` and `local-hostname` are the most useful fields)
- `network-config` (NoCloud network-config v1 or v2)

The service will detect the volume, mount it, parse the files, and apply configuration on every boot.

### CLI options

| Flag | Short | Description |
|---|---|---|
| `--help` | `-h` | Display help information |
| `--version` | `-V` | Display version and build metadata |
| `--install` | `-i` | Write and enable the systemd service unit |
| `--verbose` | `-v` | Enable debug-level logging to stderr |
| `--strict` | `-s` | Reject unknown fields in `user-data` and `network-config` (useful for catching typos) |

## Disabling
To disable execution, create the standard cloud-init disable marker:

```
touch /etc/cloud/cloud-init.disabled
```

## Wiki

- [Why nocloud-init](https://github.com/demicloud/nocloud-init/wiki/Why-nocloud-init) — Design rationale and comparison with the reference cloud-init client
- [Supported Hypervisors](https://github.com/demicloud/nocloud-init/wiki/Supported-Hypervisors) — Platforms known to generate compatible CIDATA volumes
- [Workflow](https://github.com/demicloud/nocloud-init/wiki/Workflow) — Full boot-time execution flowchart
- [FAQ](https://github.com/demicloud/nocloud-init/wiki/FAQ) — Common questions and clarifications
