# nocloud-init

## Table of Contents
- [Design Philosophy](#design-philosophy)
- [Supported Features](#supported-features)
- [Intentional Divergence from Cloud-Init](#intentional-divergence-from-cloud-init)
- [Dependencies](#dependencies)
- [Known Compatible Platforms](#known-compatible-platforms)
- [Compiling](#compiling)
  - [Using Make](#using-make-recommended)
  - [Using Go directly](#using-go-directly)
- [Installation & Usage](#installation--usage)
  - [Install the binary](#1-install-the-binary)
  - [Install and enable the systemd service](#2-install-and-enable-the-systemd-service)
  - [Provide NoCloud seed data](#3-provide-nocloud-seed-data)
  - [CLI options](#cli-options)
- [Disabling](#disabling)
- [Docs](#docs)

A minimal [NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html) datasource client. It detects a CIDATA‑labelled ISO 9660 or vfat volume, mounts it, reads `user-data`, `meta-data`, and `network-config`, and applies system configuration deterministically. If no CIDATA device is present, it exits cleanly without modifying the system.

## Design Philosophy

The reference cloud-init client is a general-purpose provisioning system designed to accommodate every cloud provider and every possible workload. That generality comes at a cost: it is large, slow, opinionated, and — critically — **designed to run only once per instance lifetime**.

`nocloud-init` makes a different trade-off: **it is stateless and runs on every boot**. This means that if you change a VM's IP address, hostname, or network configuration in your hypervisor's UI, the change takes effect on the next reboot without re-provisioning or re-deploying the VM. There is no per-instance state file, no lock file, and no "already ran" marker.

This approach is well-suited to environments where:

- A hypervisor or orchestration layer generates the CIDATA ISO automatically from a UI or API (e.g., Proxmox VE, libvirt, or a custom provisioning pipeline)
- VMs are long-lived and their configuration is expected to drift over time
- The operator wants to converge a running VM's network identity to the desired state without rebuilding it

The binary is a single static executable with no runtime dependencies beyond `chpasswd` and `ssh-keygen`. It is designed to start and complete in milliseconds, well before `systemd-networkd` begins interface configuration.

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
- `instance-id` is not used operationally (see [below](#intentional-divergence-from-cloud-init))

## Intentional Divergence from Cloud-Init

These are deliberate design decisions, not gaps.

### `instance-id` is not used to gate execution

Standard cloud-init uses `instance-id` to detect "first boot" and skip all processing on subsequent boots. `nocloud-init` does the opposite: it runs on every boot by design. The `instance-id` field is parsed and logged (at debug level) for spec compatibility, but it has no effect on whether configuration is applied.

### Remote `seedfrom` sources are not supported

The NoCloud spec allows configuration to be fetched from HTTP, HTTPS, or FTP via a `seedfrom` URL in the kernel command line or SMBIOS serial number. `nocloud-init` does not implement this because:

1. It runs *before* `systemd-networkd` starts, so the network is not available.
2. Adding URL fetching would introduce timeouts, retries, TLS handling, and a significant remote-code-execution attack surface on a binary that runs as root at boot.

Only the local CIDATA volume (Source 2 in the NoCloud spec) is supported.

### `vendor-data` is not processed

`vendor-data` exists in the spec to let a cloud provider inject defaults that tenant `user-data` can override — it is a mechanism for separating operator config from user config. In the CIDATA ISO model, the same party creates both files on the same volume, so this separation has no practical meaning. A `vendor-data` file on the volume is silently ignored.

### `chpasswd.expire` is accepted but not applied

The field is parsed for spec compatibility, but setting `expire: true` in a re-run-every-boot tool would force a password-change prompt on every reboot, which is the opposite of the intended behaviour. It is logged at debug level and otherwise ignored.

### `users` is accepted but not applied

The `users` list is parsed for spec compatibility. Proxmox VE does not populate it and full user lifecycle management (creation, SSH authorised-keys injection, sudo rules) is outside the scope of this tool. The field is silently ignored.

### Only `#cloud-config` user-data is supported

User-data formats other than `#cloud-config` (shell scripts starting with `#!`, MIME multipart, Jinja2 templates, etc.) are detected and skipped with a warning rather than producing a parse error. `nocloud-init` only implements the fields relevant to identity and network configuration.

## Dependencies
- `chpasswd` — for password updates (reads `user:hash` from stdin; the hash is never exposed in the process list)
- `ssh-keygen` — for SSH host key generation

### Network configuration
`nocloud-init` writes standard [systemd-networkd](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html) `.network` and `.link` files to `/etc/systemd/network/`. Any tool or service capable of consuming those files will work — `systemd-networkd` is the typical choice but is not a hard dependency.

## Known Compatible Platforms
- Proxmox Virtual Environment (via CIDATA ISO attachment)
- libvirt / QEMU with a cloud-init ISO (`genisoimage -volid cidata …`)
- Any hypervisor that generates a CIDATA-labelled ISO 9660 or vfat volume

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

`touch /etc/cloud/cloud-init.disabled`

## Docs

- [docs/workflow.md](docs/workflow.md) — Mermaid flowchart of the full boot-time execution path
