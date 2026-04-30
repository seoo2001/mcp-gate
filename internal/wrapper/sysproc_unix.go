//go:build !windows

package wrapper

import (
	"os/exec"
	"syscall"
)

// newSysProcAttr puts the child in its own process group so signal-fan-out
// targets the whole subtree rather than just the immediate child.
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// signalGroup sends sig to the child's entire process group.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil || pgid <= 0 {
		_ = cmd.Process.Signal(sig)
		return
	}
	_ = syscall.Kill(-pgid, sig)
}
