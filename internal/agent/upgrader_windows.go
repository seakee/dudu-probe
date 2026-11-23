//go:build windows

package agent

import (
	"os/exec"
	"time"
)

// configureTimeoutCmd 在 Windows 平台设置继承 I/O 管道等待上限，配合 CommandContext 取消回调避免阻塞。
func configureTimeoutCmd(cmd *exec.Cmd, waitDelay time.Duration) {
	if cmd == nil {
		return
	}
	cmd.WaitDelay = waitDelay
}
