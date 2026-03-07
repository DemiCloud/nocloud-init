# nocloud-init

A minimal cloud-init–compatible client implementing the NoCloud datasource. It detects a CIDATA-labeled ISO 9660 source, mounts it, reads `user-data` and `network-config`, and applies system configuration deterministically. If no CIDATA device is present, the service exits cleanly without modifying the system, making it safe for VM templates and stateless provisioning.

## Supported Features

### Network configuration
- Static addressing
- DHCP
- Multiple interfaces
- Interface renaming
- Global DNS configuration
- systemd-networkd `.network` file generation

### System identity
- Hostname updates via `hostnamectl`
- `/etc/hosts` updates for proper FQDN resolution (e.g., `hostname -f`)

### User management
- Password update for a specified user
- SSH host key generation when missing (ideal for template cloning)

## Dependencies
- systemd-networkd
- usermod
- hostnamectl
- iproute2
- ssh-keygen
- blkid

## Known Compatible Platforms
- Proxmox (via NoCloud ISO attachment)

## Disabling
To disable execution, create the standard cloud-init disable marker:

`touch /etc/cloud/cloud-init.disabled`
