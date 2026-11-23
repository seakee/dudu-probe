package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seakee/dudu-probe/internal/client"
	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
)

func TestReportOncePreservesIPv6TimestampAcrossRetriesAndCachedReuse(t *testing.T) {
	var (
		mu       sync.Mutex
		bodies   [][]byte
		attempts atomic.Int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip reader: %v", err)
			}
			defer gz.Close()
			reader = gz
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		mu.Lock()
		bodies = append(bodies, raw)
		mu.Unlock()

		// 首次请求返回 502 触发 client 重试，验证重试不改写 observed_at
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("bad gateway"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{
				"node_id":             1,
				"report_interval_sec": 10,
				"status":              "online",
			},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_agent_ipv6"
	cfg.Secret = "sec_agent_ipv6"
	cfg.HTTPTimeoutSec = 5

	col := collector.New("/")
	cli := client.New(cfg)
	ag := New(cfg, col, cli, nil)

	const sampledUnix int64 = 1700000123
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		return &collector.IPv6Observation{
			State:      collector.IPv6ObservationStateObserved,
			ObservedAt: sampledUnix,
			Address:    "2603:c020:4001:100::10",
			Assigned:   []string{"2603:c020:4001:100::10"},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 等待最小采样间隔后执行首次上报（含一次 502 重试）
	time.Sleep(120 * time.Millisecond)
	req1, ack1, err := ag.ReportOnce(ctx)
	if err != nil {
		t.Fatalf("first ReportOnce failed: %v", err)
	}
	if ack1 == nil || ack1.NodeID != 1 {
		t.Fatalf("unexpected ack1: %+v", ack1)
	}
	if req1.IPv6Observation == nil || req1.IPv6Observation.ObservedAt != sampledUnix {
		t.Fatalf("unexpected req1 IPv6Observation: %+v", req1.IPv6Observation)
	}

	// 再次调用 ReportOnce 复用缓存观测结果，ObservedAt 保持不变
	time.Sleep(120 * time.Millisecond)
	req2, _, err := ag.ReportOnce(ctx)
	if err != nil {
		t.Fatalf("second ReportOnce failed: %v", err)
	}
	if req2.IPv6Observation == nil || req2.IPv6Observation.ObservedAt != sampledUnix {
		t.Fatalf("unexpected req2 IPv6Observation: %+v", req2.IPv6Observation)
	}

	mu.Lock()
	captured := append([][]byte(nil), bodies...)
	mu.Unlock()
	if len(captured) != 3 {
		t.Fatalf("expected 3 HTTP requests (2 from retry + 1 cached reuse), got %d", len(captured))
	}
	for i, raw := range captured {
		var parsed collector.ReportRequest
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("unmarshal captured[%d]: %v", i, err)
		}
		if parsed.IPv6Observation == nil || parsed.IPv6Observation.ObservedAt != sampledUnix || parsed.IPv6Observation.Address != "2603:c020:4001:100::10" {
			t.Fatalf("captured[%d] altered ipv6_observation: %+v", i, parsed.IPv6Observation)
		}
	}
}

func TestReportOnceOmitsIPv6WhenNilAndPreservesCoreTelemetryOnUnavailable(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip reader: %v", err)
			}
			defer gz.Close()
			reader = gz
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{
				"node_id":             2,
				"report_interval_sec": 15,
				"status":              "online",
			},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_agent_safe"
	cfg.Secret = "sec_agent_safe"
	cfg.HTTPTimeoutSec = 5

	col := collector.New("/")
	cli := client.New(cfg)
	ag := New(cfg, col, cli, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 非 Linux / 非 OCI 返回 nil -> 完全省略 ipv6_observation，核心指标正常上报
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation { return nil }
	time.Sleep(120 * time.Millisecond)
	reqNil, ack, err := ag.ReportOnce(ctx)
	if err != nil || ack == nil || ack.ReportIntervalSec != 15 {
		t.Fatalf("ReportOnce with nil ipv6 failed: err=%v ack=%+v", err, ack)
	}
	if reqNil.Metrics == nil || reqNil.Metrics.SampledAt <= 0 || reqNil.IPv6Observation != nil {
		t.Fatalf("unexpected reqNil: %+v", reqNil)
	}

	// 2. 瞬时观测失败返回 unavailable -> 携带 unavailable，不影响核心指标上报
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		return &collector.IPv6Observation{
			State:      collector.IPv6ObservationStateUnavailable,
			ObservedAt: 1700000456,
		}
	}
	time.Sleep(120 * time.Millisecond)
	reqUnavail, _, err := ag.ReportOnce(ctx)
	if err != nil || reqUnavail.Metrics == nil || reqUnavail.Metrics.SampledAt <= 0 {
		t.Fatalf("ReportOnce with unavailable ipv6 failed: err=%v req=%+v", err, reqUnavail)
	}

	mu.Lock()
	captured := append([]string(nil), bodies...)
	mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(captured))
	}
	if strings.Contains(captured[0], "ipv6_observation") {
		t.Fatalf("expected nil ipv6_observation omitted from wire JSON, got %s", captured[0])
	}
	if !strings.Contains(captured[1], `"state":"unavailable"`) || strings.Contains(captured[1], `"assigned"`) || strings.Contains(captured[1], `"address"`) {
		t.Fatalf("expected clean unavailable ipv6_observation in wire JSON, got %s", captured[1])
	}
}

func TestAgentRunAndReportOnceDoNotSendOnCanceledContext(t *testing.T) {
	var registerHits atomic.Int32
	var reportHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case client.RegisterPath:
			registerHits.Add(1)
		case client.ReportPath:
			reportHits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{"node_id": 1, "report_interval_sec": 10, "status": "online"},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_cancel"
	cfg.Secret = "sec_cancel"
	cfg.HTTPTimeoutSec = 5

	col := collector.New("/")
	cli := client.New(cfg)
	ag := New(cfg, col, cli, nil)

	// 1. ReportOnce 对已取消 / 已过期上下文零请求、零采样
	var observeCalls atomic.Int32
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		observeCalls.Add(1)
		return nil
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ag.ReportOnce(canceledCtx); err == nil {
		t.Fatal("expected ReportOnce error on canceled context")
	}
	expiredCtx, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, _, err := ag.ReportOnce(expiredCtx); err == nil {
		t.Fatal("expected ReportOnce error on expired context")
	}
	if observeCalls.Load() != 0 || reportHits.Load() != 0 {
		t.Fatalf("expected 0 observe/report calls when context already canceled, got observe=%d report=%d", observeCalls.Load(), reportHits.Load())
	}

	// 2. Run 在已取消上下文中直接退出，零网络请求
	if err := ag.Run(canceledCtx); err != nil {
		t.Fatalf("expected clean exit from Run, got %v", err)
	}
	if registerHits.Load() != 0 || reportHits.Load() != 0 {
		t.Fatalf("expected 0 HTTP requests on canceled Run, got register=%d report=%d", registerHits.Load(), reportHits.Load())
	}

	// 3. ReportOnce 采样阶段中途取消后不得继续上报
	midCtx, midCancel := context.WithCancel(context.Background())
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		midCancel()
		return &collector.IPv6Observation{State: collector.IPv6ObservationStateObserved, ObservedAt: 1700000000}
	}
	if _, _, err := ag.ReportOnce(midCtx); err == nil {
		t.Fatal("expected ReportOnce error when canceled mid-collection")
	}
	if reportHits.Load() != 0 {
		t.Fatalf("expected 0 /report hits after mid-collection cancel, got %d", reportHits.Load())
	}

	// 4. Run 在 Register 返回后立即检测到取消，不得再触发 /report
	runCtx, runCancel := context.WithCancel(context.Background())
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case client.RegisterPath:
			registerHits.Add(1)
			runCancel()
		case client.ReportPath:
			reportHits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{"node_id": 1, "report_interval_sec": 10, "status": "online"},
		})
	}))
	defer regSrv.Close()
	cfg2 := config.Default()
	cfg2.ServerURL = regSrv.URL
	cfg2.NodeKey = "probe_cancel_2"
	cfg2.Secret = "sec_cancel_2"
	ag2 := New(cfg2, collector.New("/"), client.New(cfg2), nil)
	ag2.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		t.Fatal("observeIPv6 should not be called after Register-stage cancellation")
		return nil
	}
	if err := ag2.Run(runCtx); err != nil {
		t.Fatalf("expected clean exit from Run after Register cancel, got %v", err)
	}
	if reportHits.Load() != 0 {
		t.Fatalf("expected 0 /report calls after Register-stage cancel, got %d", reportHits.Load())
	}
}

func TestReportOnceSamplesIPv6BeforeVariableCollectMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{"node_id": 3, "report_interval_sec": 60, "status": "online"},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_order"
	cfg.Secret = "sec_order"
	cfg.HTTPTimeoutSec = 5

	col := collector.New("/")
	ag := New(cfg, col, client.New(cfg), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 先执行一次 CollectMetrics 使后续 CollectMetrics 触发 250ms 最小采样间隔等待
	if _, err := col.CollectMetrics(ctx); err != nil {
		t.Fatalf("warmup CollectMetrics failed: %v", err)
	}

	var observedBeforeSleep time.Duration
	start := time.Now()
	ag.observeIPv6 = func(context.Context) *collector.IPv6Observation {
		observedBeforeSleep = time.Since(start)
		return &collector.IPv6Observation{
			State:      collector.IPv6ObservationStateObserved,
			ObservedAt: time.Now().Unix(),
		}
	}
	if _, _, err := ag.ReportOnce(ctx); err != nil {
		t.Fatalf("ReportOnce failed: %v", err)
	}
	if observedBeforeSleep >= 200*time.Millisecond {
		t.Fatalf("expected IPv6 observation sampled before CollectMetrics jitter/wait, elapsed=%s", observedBeforeSleep)
	}
}
