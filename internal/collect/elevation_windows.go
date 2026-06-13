//go:build windows

package collect

import "os/exec"

// IsElevated reports whether the process is running with administrative rights.
// It uses a read-only `net session` probe, which only succeeds when elevated.
func IsElevated() bool {
	return exec.Command("net", "session").Run() == nil
}
