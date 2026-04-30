//go:build windows

package wrapper

import (
	"os/exec"
	"syscall"
)

// newSysProcAttr is a no-op on Windows; we don't ship Windows yet (per PLAN W12+),
// but the build must succeed so cross-platform CI passes.
func newSysProcAttr() *syscall.SysProcAttr { return nil }

func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(sig)
}
