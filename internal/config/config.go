// Package config 提供探针客户端的配置加载、环境变量覆盖与参数校验功能。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultConfigPath 默认配置文件路径。
	DefaultConfigPath = "/etc/dudu-probe/config.json"
	// DefaultReportIntervalSec 默认指标上报间隔（秒）。
	DefaultReportIntervalSec = 10
	// DefaultHTTPTimeoutSec 默认 HTTP 请求超时时间（秒）。
	DefaultHTTPTimeoutSec = 10
	// MinReportIntervalSec 最小允许的上报间隔（秒）。
	MinReportIntervalSec = 2
	// MaxReportIntervalSec 最大允许的上报间隔（秒）。
	MaxReportIntervalSec = 300
)

// Config 定义探针运行配置。
type Config struct {
	// ServerURL 服务端基础地址，例如 https://api.example.com
	ServerURL string `json:"server_url"`
	// NodeKey 节点唯一标识 Key
	NodeKey string `json:"node_key"`
	// Secret 节点通信密钥
	Secret string `json:"secret"`
	// ReportIntervalSec 实时指标上报间隔（秒）
	ReportIntervalSec int `json:"report_interval_sec"`
	// HTTPTimeoutSec HTTP 请求超时时间（秒）
	HTTPTimeoutSec int `json:"http_timeout_sec"`
	// InsecureTLS 是否跳过 HTTPS 证书校验
	InsecureTLS bool `json:"insecure_tls"`
	// EnableGzip 是否启用请求体 Gzip 压缩
	EnableGzip bool `json:"enable_gzip"`
	// HostRoot 容器挂载的宿主机根目录（默认 /）
	HostRoot string `json:"host_root"`
}

// Default 返回带默认值的配置实例。
func Default() *Config {
	return &Config{
		ReportIntervalSec: DefaultReportIntervalSec,
		HTTPTimeoutSec:    DefaultHTTPTimeoutSec,
		EnableGzip:        false,
		HostRoot:          "/",
	}
}

// Load 从可选配置文件与环境变量加载配置。
func Load(configPath string) (*Config, error) {
	cfg := Default()

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件 %s 失败: %w", configPath, err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件 %s 失败: %w", configPath, err)
		}
	} else if _, err := os.Stat(DefaultConfigPath); err == nil {
		if data, readErr := os.ReadFile(DefaultConfigPath); readErr == nil {
			_ = json.Unmarshal(data, cfg)
		}
	}

	cfg.ApplyEnv()
	return cfg, nil
}

// ApplyEnv 使用环境变量覆盖配置项。
func (c *Config) ApplyEnv() {
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_SERVER")); v != "" {
		c.ServerURL = v
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_KEY")); v != "" {
		c.NodeKey = v
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_SECRET")); v != "" {
		c.Secret = v
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_INTERVAL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.ReportIntervalSec = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_TIMEOUT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.HTTPTimeoutSec = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_INSECURE")); v != "" {
		c.InsecureTLS = v == "1" || strings.EqualFold(v, "true")
	}
	if v := strings.TrimSpace(os.Getenv("DUDU_PROBE_GZIP")); v != "" {
		c.EnableGzip = v == "1" || strings.EqualFold(v, "true")
	}
	if v := strings.TrimSpace(os.Getenv("HOST_ROOT")); v != "" {
		c.HostRoot = v
	}
}

// NormalizeAndValidate 规范化并校验必填配置。
func (c *Config) NormalizeAndValidate() error {
	c.ServerURL = strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
	c.NodeKey = strings.TrimSpace(c.NodeKey)
	c.Secret = strings.TrimSpace(c.Secret)

	if c.ServerURL == "" {
		return errors.New("缺少服务端地址 (server_url / --server / DUDU_PROBE_SERVER)")
	}
	if !strings.HasPrefix(c.ServerURL, "http://") && !strings.HasPrefix(c.ServerURL, "https://") {
		return errors.New("服务端地址必须以 http:// 或 https:// 开头")
	}
	if c.NodeKey == "" {
		return errors.New("缺少节点标识 (node_key / --key / DUDU_PROBE_KEY)")
	}
	if c.Secret == "" {
		return errors.New("缺少节点通信密钥 (secret / --secret / DUDU_PROBE_SECRET)")
	}

	c.ReportIntervalSec = ClampInterval(c.ReportIntervalSec)
	if c.HTTPTimeoutSec <= 0 {
		c.HTTPTimeoutSec = DefaultHTTPTimeoutSec
	}
	if c.HostRoot == "" {
		c.HostRoot = "/"
	}
	return nil
}

// ClampInterval 将上报间隔限制在安全范围内。
func ClampInterval(sec int) int {
	if sec <= 0 {
		return DefaultReportIntervalSec
	}
	if sec < MinReportIntervalSec {
		return MinReportIntervalSec
	}
	if sec > MaxReportIntervalSec {
		return MaxReportIntervalSec
	}
	return sec
}

// ReportInterval 返回上报间隔 Duration。
func (c *Config) ReportInterval() time.Duration {
	return time.Duration(ClampInterval(c.ReportIntervalSec)) * time.Second
}

// HTTPTimeout 返回 HTTP 超时 Duration。
func (c *Config) HTTPTimeout() time.Duration {
	if c.HTTPTimeoutSec <= 0 {
		return time.Duration(DefaultHTTPTimeoutSec) * time.Second
	}
	return time.Duration(c.HTTPTimeoutSec) * time.Second
}
