// Package client 提供与 dudu 探针接收服务端通信的 HTTP 客户端及签名实现。
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
	"github.com/seakee/dudu-probe/internal/version"
)

const (
	// RegisterPath 探针启动握手注册接口路径。
	RegisterPath = "/dudu/external/service/probe/register"
	// ReportPath 探针实时指标心跳上报接口路径。
	ReportPath = "/dudu/external/service/probe/report"

	// HeaderProbeKey 节点唯一标识请求头。
	HeaderProbeKey = "X-Probe-Key"
	// HeaderProbeSecret 节点通信密钥请求头（兼容直接校验）。
	HeaderProbeSecret = "X-Probe-Secret"
	// HeaderProbeTimestamp 请求 Unix 秒级时间戳请求头。
	HeaderProbeTimestamp = "X-Probe-Timestamp"
	// HeaderProbeSignature HMAC-SHA256 请求签名请求头。
	HeaderProbeSignature = "X-Probe-Signature"

	defaultMaxAttempts    = 3
	defaultRetryBaseDelay = 300 * time.Millisecond
	defaultDialTimeout    = 5 * time.Second
	defaultTCPKeepAlive   = 15 * time.Second
	defaultTLSHandshake   = 5 * time.Second
	defaultIdleConn       = 25 * time.Second
)

// PingTargetSpec 服务端下发的单条 TCP 拨测目标（目标地址已由服务端解析为 host:port）。
type PingTargetSpec struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

// ServerConfigAck 服务端在注册或心跳响应中下发的动态配置。
type ServerConfigAck struct {
	NodeID            uint             `json:"node_id"`
	ReportIntervalSec int              `json:"report_interval_sec"`
	ServerTime        int64            `json:"server_time"`
	Status            string           `json:"status"`
	TargetVersion     string           `json:"target_version,omitempty"`
	MirrorURL         string           `json:"mirror_url,omitempty"`
	PingTargets       []PingTargetSpec `json:"ping_targets,omitempty"`
}

// apiEnvelope 对应 dudu 标准 JSON 响应结构。
type apiEnvelope struct {
	Code int              `json:"code"`
	Msg  string           `json:"msg"`
	Data *ServerConfigAck `json:"data"`
}

// Client 封装向 dudu 服务端发送注册与指标数据的 HTTP 客户端。
type Client struct {
	cfg            *config.Config
	httpClient     *http.Client
	maxAttempts    int
	retryBaseDelay time.Duration
}

// New 创建新的探针上报客户端。
// 默认禁用 HTTP/2 多路复用并缩短空闲连接生命周期，防止经过 Cloudflare 代理或跨境链路时因半开死连接引发连续超时。
func New(cfg *config.Config) *Client {
	timeout := cfg.HTTPTimeout()
	dialTimeout := defaultDialTimeout
	if timeout > 0 && timeout < dialTimeout {
		dialTimeout = timeout
	}
	tlsTimeout := defaultTLSHandshake
	if timeout > 0 && timeout < tlsTimeout {
		tlsTimeout = timeout
	}
	respHeaderTimeout := 10 * time.Second
	if timeout > 0 && timeout < respHeaderTimeout {
		respHeaderTimeout = timeout
	}

	dialer := &net.Dialer{
		Timeout:       dialTimeout,
		KeepAlive:     defaultTCPKeepAlive,
		FallbackDelay: 300 * time.Millisecond,
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       defaultIdleConn,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: respHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		maxAttempts:    defaultMaxAttempts,
		retryBaseDelay: defaultRetryBaseDelay,
	}
}

// SignPayload 计算探针上报请求的 HMAC-SHA256 签名。
// 签名原文格式: nodeKey + "\n" + timestamp + "\n" + string(rawBody)
func SignPayload(nodeKey, timestamp string, rawBody []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nodeKey))
	mac.Write([]byte("\n"))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write(rawBody)
	return hex.EncodeToString(mac.Sum(nil))
}

// Register 向服务端发送节点启动握手与静态元信息注册请求。
func (c *Client) Register(ctx context.Context, meta *collector.HostMeta) (*ServerConfigAck, error) {
	return c.postJSON(ctx, RegisterPath, meta)
}

// Report 向服务端发送实时性能指标心跳包。
func (c *Client) Report(ctx context.Context, req *collector.ReportRequest) (*ServerConfigAck, error) {
	return c.postJSON(ctx, ReportPath, req)
}

func (c *Client) postJSON(ctx context.Context, path string, payload any) (*ServerConfigAck, error) {
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求数据失败: %w", err)
	}

	wireBody := rawBody
	if c.cfg.EnableGzip {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(rawBody); err != nil {
			return nil, fmt.Errorf("Gzip 压缩请求失败: %w", err)
		}
		if err := gz.Close(); err != nil {
			return nil, fmt.Errorf("关闭 Gzip 流失败: %w", err)
		}
		wireBody = buf.Bytes()
	}

	attempts := c.maxAttempts
	if attempts <= 0 {
		attempts = defaultMaxAttempts
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := c.waitRetry(ctx, attempt); err != nil {
				return nil, lastErr
			}
		}

		ack, retryable, reqErr := c.doPostAttempt(ctx, path, rawBody, wireBody, attempt)
		if reqErr == nil {
			return ack, nil
		}
		lastErr = reqErr
		if !retryable || ctx.Err() != nil {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func (c *Client) doPostAttempt(ctx context.Context, path string, rawBody, wireBody []byte, attempt int) (*ServerConfigAck, bool, error) {
	attemptTimeout := c.attemptTimeout(attempt)
	attemptCtx := ctx
	var cancel context.CancelFunc
	if attemptTimeout > 0 {
		attemptCtx, cancel = context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignPayload(c.cfg.NodeKey, timestamp, rawBody, c.cfg.Secret)

	url := c.cfg.ServerURL + path
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, url, bytes.NewReader(wireBody))
	if err != nil {
		return nil, false, fmt.Errorf("构建 HTTP 请求失败: %w", err)
	}

	// 重试时强制使用全新短连接，避免继续复用 Cloudflare 边缘或 NAT 老化连接
	if attempt > 0 {
		req.Close = true
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dudu-probe/"+version.Version)
	req.Header.Set(HeaderProbeKey, c.cfg.NodeKey)
	req.Header.Set(HeaderProbeSecret, c.cfg.Secret)
	req.Header.Set(HeaderProbeTimestamp, timestamp)
	req.Header.Set(HeaderProbeSignature, signature)
	if c.cfg.EnableGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.httpClient.CloseIdleConnections()
		return nil, true, fmt.Errorf("请求服务端 %s 失败: %w", path, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.httpClient.CloseIdleConnections()
		return nil, true, fmt.Errorf("读取服务端 %s 响应失败: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := isRetryableStatusCode(resp.StatusCode)
		if retryable {
			c.httpClient.CloseIdleConnections()
		}
		return nil, retryable, fmt.Errorf("服务端返回 HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var env apiEnvelope
	if err := json.Unmarshal(respBytes, &env); err != nil {
		c.httpClient.CloseIdleConnections()
		return nil, true, fmt.Errorf("解析服务端 JSON 响应失败: %w", err)
	}
	if env.Code != 0 {
		return nil, false, fmt.Errorf("服务端业务错误 (code=%d): %s", env.Code, env.Msg)
	}

	return env.Data, false, nil
}

// attemptTimeout 计算单次请求尝试的超时时间。
// 当基础超时 >= 10s 时，首次尝试控制在 6s、二次尝试控制在 8s，以便在遇到半开死连接或边缘节点卡顿时快速失败并重连。
func (c *Client) attemptTimeout(attempt int) time.Duration {
	base := c.cfg.HTTPTimeout()
	if base < 10*time.Second {
		return base
	}
	switch attempt {
	case 0:
		return 6 * time.Second
	case 1:
		return 8 * time.Second
	default:
		return base
	}
}

func (c *Client) waitRetry(ctx context.Context, attempt int) error {
	base := c.retryBaseDelay
	if base <= 0 {
		base = defaultRetryBaseDelay
	}
	delay := time.Duration(attempt) * base
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryableStatusCode(code int) bool {
	if code == http.StatusRequestTimeout || code == http.StatusTooManyRequests {
		return true
	}
	return code >= 500 && code <= 599
}
