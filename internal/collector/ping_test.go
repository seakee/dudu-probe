package collector

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestNormalizePingAddress(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"gd.189.cn:443", "gd.189.cn:443"},
		{"gd.189.cn", "gd.189.cn:443"},
		{"https://1.1.1.1", "1.1.1.1:443"},
		{"http://10010.com:8080/path", "10010.com:8080"},
		{"  1.1.1.1:443  ", "1.1.1.1:443"},
		{"@node:Home-OpenWrt:4433", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizePingAddress(c.in); got != c.want {
			t.Fatalf("normalizePingAddress(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsPrivateOrCarrierNAT(t *testing.T) {
	privateAddrs := []string{"10.0.0.1", "172.16.5.1", "172.31.255.254", "192.168.1.1", "100.64.0.1", "198.18.0.1", "127.0.0.1"}
	for _, addr := range privateAddrs {
		if !isPrivateOrCarrierNAT(net.ParseIP(addr)) {
			t.Fatalf("expected %s to be classified as private/CGNAT", addr)
		}
	}
	publicAddrs := []string{"111.201.97.116", "8.138.159.81", "144.24.42.242", "172.67.162.175"}
	for _, addr := range publicAddrs {
		if isPrivateOrCarrierNAT(net.ParseIP(addr)) {
			t.Fatalf("expected %s to be classified as public", addr)
		}
	}
	if isPrivateOrCarrierNAT(nil) {
		t.Fatal("expected nil IP to be treated as non-private")
	}
}

func TestSetPingTargetsFiltersAndCaps(t *testing.T) {
	col := New("/")
	targets := []PingTarget{
		{ID: "ct", Name: "广东电信", Target: "gd.189.cn:443"},
		{ID: "skip", Name: "动态节点", Target: "@node:Home-OpenWrt:4433"},
		{Name: "无ID目标", Target: "1.1.1.1"},
	}
	col.SetPingTargets(targets)

	got := col.GetPingTargets()
	if len(got) != 2 {
		t.Fatalf("expected 2 valid targets (dynamic node ref filtered), got %d: %+v", len(got), got)
	}
	if got[0].ID != "ct" || got[0].Target != "gd.189.cn:443" {
		t.Fatalf("unexpected first target: %+v", got[0])
	}
	if got[1].ID != "无ID目标" || got[1].Name != "无ID目标" || got[1].Target != "1.1.1.1:443" {
		t.Fatalf("expected fallback id/name and default port, got %+v", got[1])
	}

	// 超出上限的目标应被截断
	over := make([]PingTarget, 0, maxPingTargets+5)
	for i := 0; i < maxPingTargets+5; i++ {
		over = append(over, PingTarget{
			ID:     strconv.Itoa(i),
			Target: "127.0.0.2:" + strconv.Itoa(1000+i),
		})
	}
	col.SetPingTargets(over)
	if n := len(col.GetPingTargets()); n != maxPingTargets {
		t.Fatalf("expected targets capped at %d, got %d", maxPingTargets, n)
	}
}

func TestProbeTCPTargetLatencyAndLoss(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok := probeTCPTarget(ctx, PingTarget{ID: "local", Name: "本机", Target: ln.Addr().String()})
	if ok.LossRate != 0 {
		t.Fatalf("expected zero loss on reachable target, got %+v", ok)
	}
	if ok.LatencyMs < 0 || ok.LatencyMs > 1500 {
		t.Fatalf("unexpected latency: %+v", ok)
	}

	// 关闭的端口应判定为全丢包
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	dead := probeTCPTarget(ctx, PingTarget{ID: "dead", Name: "关闭", Target: deadAddr})
	if dead.LossRate != 100 {
		t.Fatalf("expected 100%% loss on closed port, got %+v", dead)
	}
	if dead.LatencyMs != 0 {
		t.Fatalf("expected zero latency on fully lost target, got %+v", dead)
	}
}

func TestCollectTemperaturesAndTopProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	col := New("/")
	// 预热一次以建立进程 CPU 基线
	_ = col.collectTopProcesses(ctx, 8<<30)
	time.Sleep(250 * time.Millisecond)
	procs := col.collectTopProcesses(ctx, 8<<30)
	if len(procs) > 5 {
		t.Fatalf("expected at most 5 processes, got %d", len(procs))
	}
	for _, p := range procs {
		if p.PID <= 0 || p.Name == "" {
			t.Fatalf("unexpected process snapshot: %+v", p)
		}
		if p.CPUPercent < 0 || p.CPUPercent > 100 || p.MemPercent < 0 || p.MemPercent > 100 {
			t.Fatalf("process percentages out of range: %+v", p)
		}
	}

	cpuTemp, temps := collectTemperatures(ctx, "/")
	if cpuTemp < 0 || cpuTemp >= 150 {
		t.Fatalf("unexpected cpu temperature: %f", cpuTemp)
	}
	if len(temps) > 8 {
		t.Fatalf("expected at most 8 sensors, got %d", len(temps))
	}
	for _, s := range temps {
		if s.Key == "" || s.Temperature <= 0 || s.Temperature >= 150 {
			t.Fatalf("unexpected sensor reading: %+v", s)
		}
	}
}
