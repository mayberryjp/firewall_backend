package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func daemonOwnsUDPPort(pid, port int) error {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	fds, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return fmt.Errorf("inspect daemon descriptors: %w", err)
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(root, "fd", fd.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect daemon socket ownership: %w", err)
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "net", "udp"))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		endpoint := strings.Split(fields[1], ":")
		if len(endpoint) != 2 {
			continue
		}
		bound, err := strconv.ParseUint(endpoint[1], 16, 16)
		if err == nil && int(bound) == port && inodes[fields[9]] {
			return nil
		}
	}
	return fmt.Errorf("daemon does not own an IPv4 UDP socket on port %d", port)
}

func validateDaemonBinary(path, service string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s requires an absolute operator-supplied binary path", service)
	}
	binary, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return "", fmt.Errorf("%s binary must be a root-owned executable without set-ID bits and not writable by group/others", service)
	}
	capabilityBytes, err := unix.Getxattr(binary, "security.capability", nil)
	if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return "", fmt.Errorf("inspect %s file capabilities: %w", service, err)
	}
	if capabilityBytes > 0 {
		return "", fmt.Errorf("%s binary must not carry file capabilities; capabilities are supplied to the child", service)
	}
	return binary, nil
}
