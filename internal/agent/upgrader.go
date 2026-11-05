// Package agent 实现探针主循环、握手注册、定时指标上报、动态配置同步与远程自升级。
package agent

import (
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/seakee/dudu-probe/internal/version"
)

const (
	// defaultProbeRepo 探针二进制发布仓库，用于拼接官方安装脚本地址。
	defaultProbeRepo = "seakee/dudu-probe"
	// upgradeTimeout 单次自升级脚本执行的最长等待时间。
	upgradeTimeout = 10 * time.Minute
	// upgradeRetryCooldown 升级失败后的重试冷却时间，避免每次心跳重复拉取安装脚本。
	upgradeRetryCooldown = 5 * time.Minute
)

var (
	// versionPattern 合法语义化版本号格式，防止服务端下发内容被用于命令注入。
	versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	// mirrorPattern 合法镜像地址格式。
	mirrorPattern = regexp.MustCompile(`^https?://[A-Za-z0-9._\-:/]+$`)
)

// Upgrader 负责在收到服务端下发的目标版本时异步执行探针自升级。
type Upgrader struct {
	logger      *log.Logger
	mu          sync.Mutex
	inFlight    bool
	lastAttempt time.Time
}

// NewUpgrader 创建探针自升级执行器。
func NewUpgrader(logger *log.Logger) *Upgrader {
	if logger == nil {
		logger = log.Default()
	}
	return &Upgrader{logger: logger}
}

// MaybeUpgrade 在检测到服务端下发更高目标版本时异步触发自升级（单飞执行）。
//
// 参数:
//   targetVersion: 服务端下发的目标版本号，为空表示无需升级
//   mirrorURL: 可选镜像加速前缀，为空时直连 GitHub
func (u *Upgrader) MaybeUpgrade(targetVersion, mirrorURL string) {
	target := strings.TrimSpace(targetVersion)
	if target == "" || !versionPattern.MatchString(target) {
		return
	}
	if compareVersion(target, version.Version) <= 0 {
		return
	}
	if isContainerized() {
		u.logger.Printf("[dudu-probe] 检测到容器运行环境，跳过自升级（请通过替换镜像更新到 %s）", target)
		return
	}

	u.mu.Lock()
	if u.inFlight {
		u.mu.Unlock()
		return
	}
	if !u.lastAttempt.IsZero() && time.Since(u.lastAttempt) < upgradeRetryCooldown {
		u.mu.Unlock()
		return
	}
	u.inFlight = true
	u.lastAttempt = time.Now()
	u.mu.Unlock()

	go func() {
		defer func() {
			u.mu.Lock()
			u.inFlight = false
			u.mu.Unlock()
		}()
		u.logger.Printf("[dudu-probe] 收到服务端升级指令: 当前版本=%s 目标版本=%s", version.Version, target)
		if err := u.runUpgrade(target, mirrorURL); err != nil {
			u.logger.Printf("[dudu-probe] 自升级失败（将在 %s 后重试）: %v", upgradeRetryCooldown, err)
			return
		}
		u.logger.Printf("[dudu-probe] 自升级脚本执行完成，等待服务重启")
	}()
}

func (u *Upgrader) runUpgrade(target, mirrorURL string) error {
	cmd := exec.Command("sh", "-c", buildUpgradeCommand(target, mirrorURL))
	cmd.Env = os.Environ()
	out, err := runWithTimeout(cmd, upgradeTimeout)
	if err != nil {
		if len(out) > 0 {
			u.logger.Printf("[dudu-probe] 升级命令输出: %s", strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

// buildUpgradeCommand 构造探针自升级 shell 命令。
//
// 参数:
//   target: 目标版本号，需已通过版本号格式校验
//   mirrorURL: 可选镜像加速前缀，非法地址将被忽略
//
// 返回值:
//   string: 可直接交给 sh -c 执行的命令
func buildUpgradeCommand(target, mirrorURL string) string {
	repo := strings.TrimSpace(os.Getenv("DUDU_PROBE_REPO"))
	if repo == "" {
		repo = defaultProbeRepo
	}

	scriptURL := "https://raw.githubusercontent.com/" + repo + "/main/scripts/install.sh"
	mirror := strings.TrimRight(strings.TrimSpace(mirrorURL), "/")
	if mirror != "" && !mirrorPattern.MatchString(mirror) {
		mirror = ""
	}

	var sb strings.Builder
	sb.WriteString("curl -fsSL ")
	if mirror != "" {
		sb.WriteString(shellQuote(mirror + "/" + scriptURL))
	} else {
		sb.WriteString(shellQuote(scriptURL))
	}
	sb.WriteString(" | ")
	if os.Geteuid() != 0 {
		// 非 root 场景（如 QNAP admin 账号）需要免密 sudo，失败则直接报错退出
		sb.WriteString("sudo -n ")
	}
	sb.WriteString("bash -s -- ")
	if mirror != "" {
		sb.WriteString("--mirror ")
		sb.WriteString(shellQuote(mirror))
		sb.WriteString(" ")
	}
	sb.WriteString("--version ")
	sb.WriteString(shellQuote(target))
	sb.WriteString(" upgrade")
	return sb.String()
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	done := make(chan struct{})
	var out []byte
	var err error

	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return out, err
	case <-timer.C:
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return out, errUpgradeTimeout
	}
}

type upgradeTimeoutError struct{}

func (upgradeTimeoutError) Error() string { return "升级脚本执行超时" }

var errUpgradeTimeout = upgradeTimeoutError{}

// isContainerized 判断探针是否运行在容器环境中（容器内自升级无意义）。
func isContainerized() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return false
}

// compareVersion 比较两个语义化版本号，返回 -1 / 0 / 1。
func compareVersion(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// 兼容带构建元数据的版本号，如 1.2.3-rc1+build
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out[i] = n
	}
	return out
}

// shellQuote 使用单引号包裹参数，避免命令注入。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
