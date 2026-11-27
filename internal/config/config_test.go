package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndValidate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")
	raw := `{
		"server_url": "https://api.example.com/",
		"node_key": "probe_test_01",
		"secret": "sec_123456",
		"report_interval_sec": 1,
		"http_timeout_sec": 5
	}`
	if err := os.WriteFile(cfgFile, []byte(raw), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("NormalizeAndValidate failed: %v", err)
	}

	if cfg.ServerURL != "https://api.example.com" {
		t.Fatalf("expected trimmed server_url, got %q", cfg.ServerURL)
	}
	if cfg.ReportIntervalSec != MinReportIntervalSec {
		t.Fatalf("expected clamped interval %d, got %d", MinReportIntervalSec, cfg.ReportIntervalSec)
	}
}

func TestApplyEnvAndMissingFields(t *testing.T) {
	t.Setenv("DUDU_PROBE_SERVER", "http://127.0.0.1:8000")
	t.Setenv("DUDU_PROBE_KEY", "probe_env_key")
	t.Setenv("DUDU_PROBE_SECRET", "probe_env_secret")
	t.Setenv("DUDU_PROBE_INTERVAL", "15")

	cfg := Default()
	cfg.ApplyEnv()
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ReportIntervalSec != 15 {
		t.Fatalf("expected interval 15, got %d", cfg.ReportIntervalSec)
	}

	invalid := Default()
	if err := invalid.NormalizeAndValidate(); err == nil {
		t.Fatal("expected validation error for empty config")
	}
}

func TestDialNetworkNormalizationAndEnv(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", DialNetworkIPv4First},
		{"ipv4_first", DialNetworkIPv4First},
		{"prefer_ipv4", DialNetworkIPv4First},
		{"IPv4", DialNetworkTCP4},
		{"tcp4", DialNetworkTCP4},
		{"ipv6", DialNetworkTCP6},
		{"tcp6", DialNetworkTCP6},
		{"auto", DialNetworkAuto},
		{"tcp", DialNetworkAuto},
	}
	for _, tc := range cases {
		got, err := NormalizeDialNetwork(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeDialNetwork(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	if _, err := NormalizeDialNetwork("udp4"); err == nil {
		t.Fatal("expected error for invalid dial_network")
	}

	t.Setenv("DUDU_PROBE_SERVER", "https://api.example.com")
	t.Setenv("DUDU_PROBE_KEY", "k")
	t.Setenv("DUDU_PROBE_SECRET", "s")
	t.Setenv("DUDU_PROBE_DIAL_NETWORK", "tcp4")
	cfg := Default()
	cfg.ApplyEnv()
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("NormalizeAndValidate failed: %v", err)
	}
	if cfg.DialNetwork != DialNetworkTCP4 {
		t.Fatalf("expected DialNetwork %q, got %q", DialNetworkTCP4, cfg.DialNetwork)
	}
}
