//go:build !windows

package collect

import (
	"errors"
	"os"
)

// IsElevated reports whether the process has elevated privileges. On non-Windows
// platforms this is approximated by a root (uid 0) check.
func IsElevated() bool { return os.Geteuid() == 0 }

// Relaunch is a no-op on non-Windows platforms, where there is no UAC.
func Relaunch() error { return errors.New("self-elevation is only supported on Windows") }
