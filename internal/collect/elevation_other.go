//go:build !windows

package collect

import "os"

// IsElevated reports whether the process has elevated privileges. On non-Windows
// platforms this is approximated by a root (uid 0) check.
func IsElevated() bool { return os.Geteuid() == 0 }
