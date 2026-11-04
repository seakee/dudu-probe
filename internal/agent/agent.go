// Package agent 实现探针主循环、握手注册、定时指标上报与动态配置同步。
package agent

import (
	"context"
	"log"
	"time"

	"github.com/seakee/dudu-probe/internal/client"
	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
)

// Agent 负责管理探针完整运行周期。
type Agent struct {
	cfg       *config.Config
	collector *collector.Collector
	client    *client.Client
	logger    *log.Logger
}

// New 创建探针 Agent 实例。
func New(cfg *config.Config, col *collector.Collector, cli *client.Client, logger *log.Logger) *Agent {
	if logger == nil {
		logger = log.Default()
	}
	return &Agent{
		cfg:       cfg,
		collector: col,
		client:    cli,
		logger:    logger,
	}
}

// Run 启动探针常驻循环，直到 ctx 取消。
func (a *Agent) Run(ctx context.Context) error {
	interval := a.cfg.ReportInterval()
	a.logger.Printf("[dudu-probe] 启动成功，目标服务端=%s 节点Key=%s 初始上报间隔=%s",
		a.cfg.ServerURL, a.cfg.NodeKey, interval)

	// 1. 首次启动握手注册
	meta := a.collector.CollectHostMeta(ctx, true)
	if ack, err := a.client.Register(ctx, meta); err != nil {
		a.logger.Printf("[dudu-probe] 首次注册握手失败（将在后续心跳中自动重试）: %v", err)
	} else {
		a.logger.Printf("[dudu-probe] 节点注册握手成功 (hostname=%s, os=%s/%s, cores=%d)",
			meta.Hostname, meta.OSName, meta.Arch, meta.CPUCores)
		if ack != nil && ack.ReportIntervalSec > 0 {
			newInterval := time.Duration(config.ClampInterval(ack.ReportIntervalSec)) * time.Second
			if newInterval != interval {
				interval = newInterval
				a.logger.Printf("[dudu-probe] 同步服务端下发上报间隔: %s", interval)
			}
		}
	}

	// 2. 立即执行一次指标上报
	if newInterval := a.reportOnce(ctx, interval); newInterval != interval {
		interval = newInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
			return nil
		case <-ticker.C:
			if newInterval := a.reportOnce(ctx, interval); newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
				a.logger.Printf("[dudu-probe] 动态调整上报间隔为: %s", interval)
			}
		}
	}
}

// ReportOnce 执行单次采集与上报，可用于 CLI -once 模式或定时循环。
func (a *Agent) ReportOnce(ctx context.Context) (*collector.ReportRequest, *client.ServerConfigAck, error) {
	meta := a.collector.CollectHostMeta(ctx, false)
	metrics, err := a.collector.CollectMetrics(ctx)
	if err != nil {
		return nil, nil, err
	}
	req := &collector.ReportRequest{
		Host:    meta,
		Metrics: metrics,
	}
	ack, err := a.client.Report(ctx, req)
	return req, ack, err
}

func (a *Agent) reportOnce(ctx context.Context, currentInterval time.Duration) time.Duration {
	_, ack, err := a.ReportOnce(ctx)
	if err != nil {
		a.logger.Printf("[dudu-probe] 指标上报失败: %v", err)
		return currentInterval
	}
	if ack != nil && ack.ReportIntervalSec > 0 {
		next := time.Duration(config.ClampInterval(ack.ReportIntervalSec)) * time.Second
		return next
	}
	return currentInterval
}
