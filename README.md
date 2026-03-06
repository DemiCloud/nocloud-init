# SO-nocloud-init
A Go implementation of cloud-init, using the [NoCloud](https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html) standard. Works with Proxmox. Detects a NoCloud ISO 9660 CD-ROM image with the label "CIDATA" or "cidata", and mounts it, then parses the NoCloud configuration files.

## Supports:
* Network Configuration
  * Static IPs
  * Multiple Interfaces
  * Renames interfaces
  * Configures Global DNS
  * DHCP
* Hostname update
  * Updates `hostnamectl`
  * Updates `/etc/hosts` to properly support an FQDN, E.G. via `hostname -f`
* Update password for specified user
* Regenerate host ssh keys if they don't exist (E.G. for cloning from templates)

## Dependencies
* systemd-networkd
* usermod
* hostnamectl
* iproute2
* ssh-keygen
* blkid

## Disable
Compliant with Cloud-init. `touch /etc/cloud/cloud-init.disabled` will stop the service from running.
