package agent

import (
	"os/exec"
	"strings"
	"testing"
	"time"
	"github.com/seakee/dudu-probe/internal/client"
	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
)

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.1.0", "1.0.4", 1},
		{"1.1.0", "1.1.0", 0},
		{"1.0.10", "1.0.9", 1},
		{"1.0.4", "v1.1.0", -1},
		{"v2.0.0", "1.9.9", 1},
		{"1.2.3-rc1", "1.2.3", 0},
		{"1.2.3+build", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := compareVersion(c.a, c.b); got != c.want {
			t.Fatalf("compareVersion(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionAndMirrorPatternValidation(t *testing.T) {
	valid := []string{"v1.1.0", "1.1.0", "v0.0.1"}
	for _, v := range valid {
		if !versionPattern.MatchString(v) {
			t.Fatalf("expected %q to be a valid version", v)
		}
	}
	// 拒绝命令注入与非法版本
	invalid := []string{"", "1.1", "v1.1.0; rm -rf /", "v1.1.0 && curl evil", "../1.1.0", "latest"}
	for _, v := range invalid {
		if versionPattern.MatchString(v) {
			t.Fatalf("expected %q to be rejected", v)
		}
	}

	if !mirrorPattern.MatchString("https://ghfast.top") {
		t.Fatal("expected mirror url to be accepted")
	}
	if mirrorPattern.MatchString("https://ghfast.top; rm -rf /") {
		t.Fatal("expected shell metacharacters in mirror url to be rejected")
	}
}

func TestMaybeUpgradeSkipsWhenNotNewer(t *testing.T) {
	u := NewUpgrader(nil)

	// 空版本、非法版本、同版本、更低版本均不应触发
	u.MaybeUpgrade("", "")
	u.MaybeUpgrade("not-a-version", "")
	u.MaybeUpgrade("v0.0.1", "")

	u.mu.Lock()
	inFlight := u.inFlight
	lastAttempt := u.lastAttempt
	u.mu.Unlock()

	if inFlight {
		t.Fatal("expected no upgrade flight for non-newer versions")
	}
	if !lastAttempt.IsZero() {
		t.Fatal("expected lastAttempt to stay zero when no upgrade is triggered")
	}
}

func TestBuildUpgradeCommand(t *testing.T) {
	withMirror := buildUpgradeCommand("v1.2.0", "https://ghfast.top/")
	if !strings.Contains(withMirror, "ghfast.top/https://raw.githubusercontent.com/seakee/dudu-probe/main/scripts/install.sh") {
		t.Fatalf("expected mirrored script url, got %q", withMirror)
	}
	if !strings.Contains(withMirror, "--mirror 'https://ghfast.top'") {
		t.Fatalf("expected mirror flag, got %q", withMirror)
	}
	if !strings.Contains(withMirror, "--version 'v1.2.0'") {
		t.Fatalf("expected version flag, got %q", withMirror)
	}
	if !strings.HasSuffix(withMirror, " upgrade") {
		t.Fatalf("expected upgrade subcommand at tail, got %q", withMirror)
	}

	plain := buildUpgradeCommand("v1.2.0", "")
	if strings.Contains(plain, "--mirror") {
		t.Fatalf("expected no mirror flag, got %q", plain)
	}
	if !strings.Contains(plain, "raw.githubusercontent.com/seakee/dudu-probe") {
		t.Fatalf("expected official script url, got %q", plain)
	}

	// 非法镜像地址必须被丢弃，避免命令注入
	bad := buildUpgradeCommand("v1.2.0", "https://evil.example.com; rm -rf /")
	if strings.Contains(bad, "--mirror") || strings.Contains(bad, "rm -rf") {
		t.Fatalf("expected illegal mirror to be dropped, got %q", bad)
	}
}

func TestBuildUpgradeCommandHonorsRepoOverride(t *testing.T) {
	t.Setenv("DUDU_PROBE_REPO", "example/fork-probe")
	cmd := buildUpgradeCommand("v1.2.0", "")
	if !strings.Contains(cmd, "raw.githubusercontent.com/example/fork-probe/main/scripts/install.sh") {
		t.Fatalf("expected repo override in script url, got %q", cmd)
	}
}

func TestApplyAckSyncsAndClearsPingTargets(t *testing.T) {
	col := collector.New("/")
	ag := New(&config.Config{}, col, nil, nil)

	ag.applyAck(&client.ServerConfigAck{
		PingTargets: []client.PingTargetSpec{
			{ID: "ct-gd", Name: "广东电信", Target: "gd.189.cn:443"},
		},
	})
	if got := col.GetPingTargets(); len(got) != 1 || got[0].ID != "ct-gd" {
		t.Fatalf("expected 1 ping target synced from ack, got %+v", got)
	}

	// 服务端下发空拨测列表时应清空本地已缓存目标
	ag.applyAck(&client.ServerConfigAck{
		PingTargets: nil,
	})
	if got := col.GetPingTargets(); len(got) != 0 {
		t.Fatalf("expected ping targets cleared when ack carries empty list, got %+v", got)
	}
}

func TestRunWithTimeoutReturnsOnTimeout(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 5")
	start := time.Now()
	_, err := runWithTimeout(cmd, 80*time.Millisecond)
	if err != errUpgradeTimeout {
		t.Fatalf("expected errUpgradeTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("expected runWithTimeout to return promptly, took %s", elapsed)
	}
}
