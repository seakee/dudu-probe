package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
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
