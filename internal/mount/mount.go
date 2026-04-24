package mount

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrCIDATANotFound = errors.New("CIDATA device not found")

func findCIDATADevice() (string, error) {
	entries, err := os.ReadDir("/dev/disk/by-label")
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EIO) {
			return "", ErrCIDATANotFound
		}
		return "", fmt.Errorf("ReadDir /dev/disk/by-label: %w", err)
	}

	for _, e := range entries {
		if strings.EqualFold(e.Name(), "CIDATA") {
			return "/dev/disk/by-label/" + e.Name(), nil
		}
	}

	return "", ErrCIDATANotFound
}

func MountISO(mountPoint string) (string, error) {
	device, err := findCIDATADevice()
	if err != nil {
		if errors.Is(err, ErrCIDATANotFound) {
			return "", ErrCIDATANotFound
		}
		return "", err
	}

	if err := unix.Mount(device, mountPoint, "iso9660", unix.MS_RDONLY, ""); err != nil {
		return "", fmt.Errorf("failed to mount %s: %v", device, err)
	}

	return device, nil
}

func UnmountISO(mountPoint string) error {
	if err := unix.Unmount(mountPoint, 0); err != nil {
		return fmt.Errorf("failed to unmount %s: %v", mountPoint, err)
	}
	return nil
}
