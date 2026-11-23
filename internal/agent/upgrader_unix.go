//go:build unix

package agent

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// configureTimeoutCmd 在 Unix 平台启用独立进程组与整组强杀，并设置管道等待上限避免孤儿进程阻塞。
func configureTimeoutCmd(cmd *exec.Cmd, waitDelay time.Duration) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.WaitDelay = waitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		if err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
