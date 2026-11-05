// Package collector 提供服务器静态元信息与动态实时指标的跨平台采集能力。
package collector

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// maxPingTargets 单次心跳最大并发拨测目标数量上限。
	maxPingTargets = 12
	// pingAttemptsPerTarget 单个目标每轮 TCP 握手采样次数。
	pingAttemptsPerTarget = 2
	// singlePingTimeout 单次 TCP 握手超时时间。
	singlePingTimeout = 1500 * time.Millisecond
)

// SetPingTargets 更新采集器缓存的 TCP 拨测目标列表。
func (c *Collector) SetPingTargets(targets []PingTarget) {
	c.pingMu.Lock()
	defer c.pingMu.Unlock()

	cleaned := make([]PingTarget, 0, len(targets))
	for _, t := range targets {
		addr := normalizePingAddress(t.Target)
		if addr == "" {
			continue
		}
		id := strings.TrimSpace(t.ID)
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = addr
		}
		if id == "" {
			id = name
		}
		cleaned = append(cleaned, PingTarget{
			ID:     id,
			Name:   name,
			Target: addr,
		})
		if len(cleaned) >= maxPingTargets {
			break
		}
	}
	c.pingTargets = cleaned
}

// GetPingTargets 获取当前缓存的拨测目标列表副本。
func (c *Collector) GetPingTargets() []PingTarget {
	c.pingMu.RLock()
	defer c.pingMu.RUnlock()

	if len(c.pingTargets) == 0 {
		return nil
	}
	out := make([]PingTarget, len(c.pingTargets))
	copy(out, c.pingTargets)
	return out
}

// collectPingResults 并发执行所有已配置目标的轻量 TCP Ping 测速。
func (c *Collector) collectPingResults(ctx context.Context) []PingStat {
	targets := c.GetPingTargets()
	if len(targets) == 0 {
		return nil
	}

	results := make([]PingStat, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt PingTarget) {
			defer wg.Done()
			results[idx] = probeTCPTarget(ctx, tgt)
		}(i, target)
	}
	wg.Wait()
	return results
}

func probeTCPTarget(ctx context.Context, tgt PingTarget) PingStat {
	stat := PingStat{
		ID:     tgt.ID,
		Name:   tgt.Name,
		Target: tgt.Target,
	}

	var successCount int
	var latencySumMs float64

	for i := 0; i < pingAttemptsPerTarget; i++ {
		if ctx.Err() != nil {
			break
		}
		dialer := net.Dialer{
			Timeout: singlePingTimeout,
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", tgt.Target)
		elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0
		if err == nil && conn != nil {
			_ = conn.Close()
			successCount++
			latencySumMs += elapsedMs
		}
	}

	if successCount > 0 {
		stat.LatencyMs = round2(latencySumMs / float64(successCount))
	}
	failed := pingAttemptsPerTarget - successCount
	stat.LossRate = round2(float64(failed) * 100.0 / float64(pingAttemptsPerTarget))
	return stat
}

func normalizePingAddress(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "@node:") {
		return ""
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "tcp://")
	if slashIdx := strings.IndexByte(s, '/'); slashIdx >= 0 {
		s = s[:slashIdx]
	}
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "443")
}
