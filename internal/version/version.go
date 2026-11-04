// Package version 提供探针编译版本元信息管理。
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version 探针语义化版本号，编译时通过 -ldflags 注入。
	Version = "1.0.0"
	// Commit Git 提交短哈希，编译时通过 -ldflags 注入。
	Commit = "dev"
	// BuildDate 构建时间（UTC），编译时通过 -ldflags 注入。
	BuildDate = "unknown"
)

// Info 返回完整版本描述字符串。
func Info() string {
	return fmt.Sprintf("dudu-probe v%s (commit=%s, built=%s, go=%s, os=%s/%s)",
		Version, Commit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
