# nocloud-init

## Table of Contents
- [Supported Features](#supported-features)
- [Dependencies](#dependencies)
- [Known Compatible Platforms](#known-compatible-platforms)
- [Compiling](#compiling)
  - [Using Make](#using-make-recommended)
  - [Using Go directly](#using-go-directly)
- [Installation & Usage](#installation--usage)
  - [Install the binary](#1-install-the-binary)
  - [Install and enable the systemd service](#2-install-and-enable-the-systemd-service)
  - [Provide NoCloud seed data](#3-provide-nocloud-seed-data)
- [Disabling](#disabling)

A minimal cloud-init–compatible client implementing the NoCloud datasource. It detects a CIDATA‑labeled ISO 9660 source, mounts it, reads `user-data` and `network-config`, and applies system configuration deterministically. If no CIDATA device is present, it exits cleanly without modifying the system, making it safe for VM templates and stateless provisioning.

## Supported Features

### Network configuration
- Static addressing
- DHCP
- Multiple interfaces
- Interface renaming
- Global DNS configuration
- systemd-networkd `.network` file generation

### System identity
- Hostname updates
- `/etc/hosts` updates for proper FQDN resolution (e.g., `hostname -f`)

### User management
- Password update for a specified user
- SSH host key generation when missing (ideal for template cloning)

## Dependencies
- `usermod` — for password updates
- `ssh-keygen` — for SSH host key generation

### Network configuration
nocloud-init writes standard [systemd-networkd](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html) `.network` and `.link` files to `/etc/systemd/network/`. Any tool or service capable of consuming those files will work — systemd-networkd is the typical choice, but it is not a hard requirement.

## Known Compatible Platforms
- Proxmox Virtual Environment (via CIDATA ISO attachment)

## Compiling

### Using Make (recommended)
Running `make` builds the binary into `build/nocloud-init`.

### Using Go directly
`go build -o build/nocloud-init main.go`

## Installation & Usage

### 1. Install the binary
Place the compiled binary anywhere on the system. It does **not** need to be in PATH because the installer generates a systemd service with the correct absolute ExecStart path.

Example:

`sudo install -m 0755 build/nocloud-init /usr/local/sbin/nocloud-init`

### 2. Install and enable the systemd service
Install the generated service file at:

`/etc/systemd/system/nocloud-init.service`

Then enable and start it:

`sudo systemctl enable --now nocloud-init.service`

### 3. Provide NoCloud seed data
Attach a CIDATA‑labeled ISO containing:

- `user-data`
- `meta-data` (optional)
- `network-config` (optional)

The service will detect, mount, parse, and apply configuration on boot.

## Disabling
To disable execution, create the standard cloud-init disable marker:

`touch /etc/cloud/cloud-init.disabled`
