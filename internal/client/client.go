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
)

// ServerConfigAck 服务端在注册或心跳响应中下发的动态配置。
type ServerConfigAck struct {
	NodeID            uint   `json:"node_id"`
	ReportIntervalSec int    `json:"report_interval_sec"`
	ServerTime        int64  `json:"server_time"`
	Status            string `json:"status"`
}

// apiEnvelope 对应 dudu 标准 JSON 响应结构。
type apiEnvelope struct {
	Code int              `json:"code"`
	Msg  string           `json:"msg"`
	Data *ServerConfigAck `json:"data"`
}

// Client 封装向 dudu 服务端发送注册与指标数据的 HTTP 客户端。
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

// New 创建新的探针上报客户端。
func New(cfg *config.Config) *Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        10,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   cfg.HTTPTimeout(),
			Transport: tr,
		},
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

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignPayload(c.cfg.NodeKey, timestamp, rawBody, c.cfg.Secret)

	var bodyReader io.Reader
	if c.cfg.EnableGzip {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(rawBody); err != nil {
			return nil, fmt.Errorf("Gzip 压缩请求失败: %w", err)
		}
		if err := gz.Close(); err != nil {
			return nil, fmt.Errorf("关闭 Gzip 流失败: %w", err)
		}
		bodyReader = &buf
	} else {
		bodyReader = bytes.NewReader(rawBody)
	}

	url := c.cfg.ServerURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("构建 HTTP 请求失败: %w", err)
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
		return nil, fmt.Errorf("请求服务端 %s 失败: %w", path, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取服务端响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("服务端返回 HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	var env apiEnvelope
	if err := json.Unmarshal(respBytes, &env); err != nil {
		return nil, fmt.Errorf("解析服务端 JSON 响应失败: %w", err)
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("服务端业务错误 (code=%d): %s", env.Code, env.Msg)
	}

	return env.Data, nil
}
