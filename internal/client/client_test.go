package client

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
	"github.com/seakee/dudu-probe/internal/version"
)

func TestRegisterAndReportSignature(t *testing.T) {
	const (
		testKey    = "probe_unit_key"
		testSecret = "sec_unit_secret"
	)

	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		gotKey := r.Header.Get(HeaderProbeKey)
		gotSecret := r.Header.Get(HeaderProbeSecret)
		gotTS := r.Header.Get(HeaderProbeTimestamp)
		gotSig := r.Header.Get(HeaderProbeSignature)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		expectedSig := SignPayload(testKey, gotTS, body, testSecret)
		if gotKey != testKey || gotSecret != testSecret || gotSig != expectedSig {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{
				"node_id":             1,
				"report_interval_sec": 15,
				"status":              "online",
			},
		})
	}))
	defer srv.Close()

	cfg := &config.Config{
		ServerURL:         srv.URL,
		NodeKey:           testKey,
		Secret:            testSecret,
		ReportIntervalSec: 10,
		HTTPTimeoutSec:    5,
	}
	cli := New(cfg)

	ack, err := cli.Register(context.Background(), &collector.HostMeta{
		Hostname: "unit-host",
		OSName:   "linux",
		Arch:     "amd64",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if receivedPath != RegisterPath || ack.ReportIntervalSec != 15 {
		t.Fatalf("unexpected register result: path=%s ack=%+v", receivedPath, ack)
	}

	ack, err = cli.Report(context.Background(), &collector.ReportRequest{
		Metrics: &collector.MetricPayload{
			SampledAt: 1700000000,
			CPUUsage:  12.5,
			MemUsage:  45.0,
		},
	})
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}
	if receivedPath != ReportPath || ack.NodeID != 1 {
		t.Fatalf("unexpected report result: path=%s ack=%+v", receivedPath, ack)
	}
}

func TestRetryOnCloudflare52xAndGzipPayload(t *testing.T) {
	const (
		testKey    = "probe_cf_key"
		testSecret = "sec_cf_secret"
	)

	var attempts int32
	var sawCloseOnRetry atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&attempts, 1)
		if cur > 1 && r.Close {
			sawCloseOnRetry.Store(true)
		}

		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip reader: %v", err)
			}
			defer gz.Close()
			reader = gz
		}
		rawBody, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		expectedSig := SignPayload(testKey, r.Header.Get(HeaderProbeTimestamp), rawBody, testSecret)
		if r.Header.Get(HeaderProbeSignature) != expectedSig {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// 前两次模拟 Cloudflare 522 / 524 边缘回源超时错误
		if cur == 1 {
			w.WriteHeader(522)
			_, _ = w.Write([]byte("Origin Connection Time-out"))
			return
		}
		if cur == 2 {
			w.WriteHeader(524)
			_, _ = w.Write([]byte("A Timeout Occurred"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{
				"node_id":             8,
				"report_interval_sec": 10,
				"status":              "online",
			},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = testKey
	cfg.Secret = testSecret

	cli := New(cfg)
	cli.retryBaseDelay = 10 * time.Millisecond

	tr, ok := cli.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.ForceAttemptHTTP2 || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
		t.Fatal("expected HTTP/2 to be explicitly disabled for probe transport")
	}

	ack, err := cli.Report(context.Background(), &collector.ReportRequest{
		Metrics: &collector.MetricPayload{
			SampledAt: 1700000100,
			CPUUsage:  8.2,
		},
	})
	if err != nil {
		t.Fatalf("expected Report to succeed after CF 52x retries, got error: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
	if !sawCloseOnRetry.Load() {
		t.Fatal("expected retry request to set req.Close = true for fresh TCP connection")
	}
	if ack == nil || ack.NodeID != 8 {
		t.Fatalf("unexpected ack: %+v", ack)
	}
}

func TestReportAckCarriesUpgradeAndPingTargets(t *testing.T) {
	var gotUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"msg":  "ok",
			"data": map[string]any{
				"node_id":             9,
				"report_interval_sec": 10,
				"status":              "online",
				"target_version":      "v1.1.0",
				"mirror_url":          "https://ghfast.top",
				"ping_targets": []map[string]any{
					{"id": "ct-gd", "name": "广东电信", "target": "gd.189.cn:443"},
					{"id": "cu-bj", "name": "北京联通", "target": "111.201.97.116:4433"},
				},
			},
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_ack_key"
	cfg.Secret = "sec_ack_secret"

	cli := New(cfg)
	ack, err := cli.Report(context.Background(), &collector.ReportRequest{
		Metrics: &collector.MetricPayload{
			SampledAt: 1700000200,
			CPUUsage:  12.5,
			CPUTemp:   52.3,
			Temperatures: []collector.SensorTemp{
				{Key: "cpu-thermal", Temperature: 52.3},
			},
			TopProcesses: []collector.ProcessStat{
				{PID: 1234, Name: "ffmpeg", CPUPercent: 42.1, MemPercent: 8.5, MemRSS: 512 << 20},
			},
			PingResults: []collector.PingStat{
				{ID: "ct-gd", Name: "广东电信", Target: "gd.189.cn:443", LatencyMs: 168.4, LossRate: 0},
			},
		},
	})
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}
	if ack == nil {
		t.Fatal("expected non-nil ack")
	}
	if ack.TargetVersion != "v1.1.0" || ack.MirrorURL != "https://ghfast.top" {
		t.Fatalf("unexpected upgrade payload in ack: %+v", ack)
	}
	if len(ack.PingTargets) != 2 {
		t.Fatalf("expected 2 ping targets, got %+v", ack.PingTargets)
	}
	if ack.PingTargets[1].Name != "北京联通" || ack.PingTargets[1].Target != "111.201.97.116:4433" {
		t.Fatalf("unexpected ping target: %+v", ack.PingTargets[1])
	}
	if gotUserAgent != "dudu-probe/"+version.Version {
		t.Fatalf("unexpected user agent: %q", gotUserAgent)
	}
}

func TestNoRetryOnUnauthorized(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.NodeKey = "probe_k"
	cfg.Secret = "probe_s"

	cli := New(cfg)
	cli.retryBaseDelay = 5 * time.Millisecond

	_, err := cli.Register(context.Background(), &collector.HostMeta{Hostname: "h"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected no retry on 401, got %d attempts", atomic.LoadInt32(&attempts))
	}
}
