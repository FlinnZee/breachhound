//go:build windows

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the process is running with administrative rights.
// It uses a read-only `net session` probe, which only succeeds when elevated.
func IsElevated() bool {
	return exec.Command("net", "session").Run() == nil
}

const swShowNormal int32 = 1

// Relaunch restarts the current executable with a UAC elevation prompt,
// preserving the original command-line arguments. On success the elevated
// instance starts and the caller should exit; if the user declines the prompt
// an error is returned and the current process keeps running unelevated.
func Relaunch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	args, err := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	if err != nil {
		return err
	}
	cwd, err := syscall.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, args, cwd, swShowNormal)
}
