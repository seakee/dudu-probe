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
	cfg         *config.Config
	collector   *collector.Collector
	client      *client.Client
	logger      *log.Logger
	upgrader    *Upgrader
	observeIPv6 func(context.Context) *collector.IPv6Observation
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
		upgrader:  NewUpgrader(logger),
	}
}

// applyAck 应用服务端下发的动态配置（拨测目标、目标版本）。
func (a *Agent) applyAck(ack *client.ServerConfigAck) {
	if ack == nil {
		return
	}
	if a.collector != nil {
		targets := make([]collector.PingTarget, 0, len(ack.PingTargets))
		for _, t := range ack.PingTargets {
			targets = append(targets, collector.PingTarget{
				ID:     t.ID,
				Name:   t.Name,
				Target: t.Target,
			})
		}
		a.collector.SetPingTargets(targets)
	}
	if a.upgrader != nil {
		a.upgrader.MaybeUpgrade(ack.TargetVersion, ack.MirrorURL)
	}
}

// Run 启动探针常驻循环，直到 ctx 取消。
func (a *Agent) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
		return nil
	}

	interval := a.cfg.ReportInterval()
	a.logger.Printf("[dudu-probe] 启动成功，目标服务端=%s 节点Key=%s 初始上报间隔=%s",
		a.cfg.ServerURL, a.cfg.NodeKey, interval)

	// 1. 首次启动握手注册
	meta := a.collector.CollectHostMeta(ctx, true)
	if ctx.Err() != nil {
		a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
		return nil
	}
	if ack, err := a.client.Register(ctx, meta); err != nil {
		if ctx.Err() != nil {
			a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
			return nil
		}
		a.logger.Printf("[dudu-probe] 首次注册握手失败（将在后续心跳中自动重试）: %v", err)
	} else {
		if ctx.Err() != nil {
			a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
			return nil
		}
		a.logger.Printf("[dudu-probe] 节点注册握手成功 (hostname=%s, os=%s/%s, cores=%d)",
			meta.Hostname, meta.OSName, meta.Arch, meta.CPUCores)
		if ack != nil && ack.ReportIntervalSec > 0 {
			newInterval := time.Duration(config.ClampInterval(ack.ReportIntervalSec)) * time.Second
			if newInterval != interval {
				interval = newInterval
				a.logger.Printf("[dudu-probe] 同步服务端下发上报间隔: %s", interval)
			}
		}
		a.applyAck(ack)
	}

	if ctx.Err() != nil {
		a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
		return nil
	}

	// 2. 立即执行一次指标上报
	if newInterval := a.reportOnce(ctx, interval); newInterval != interval {
		interval = newInterval
	}
	if ctx.Err() != nil {
		a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil {
			a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
			return nil
		}
		select {
		case <-ctx.Done():
			a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
			return nil
		case <-ticker.C:
			if ctx.Err() != nil {
				a.logger.Printf("[dudu-probe] 收到退出信号，停止探针服务")
				return nil
			}
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
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var ipv6Obs *collector.IPv6Observation
	if a.observeIPv6 != nil {
		ipv6Obs = a.observeIPv6(ctx)
	} else if a.collector != nil {
		ipv6Obs = a.collector.CollectIPv6Observation(ctx, false)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	meta := a.collector.CollectHostMeta(ctx, false)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	metrics, err := a.collector.CollectMetrics(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	req := &collector.ReportRequest{
		Host:            meta,
		Metrics:         metrics,
		IPv6Observation: ipv6Obs,
	}
	ack, err := a.client.Report(ctx, req)
	return req, ack, err
}

func (a *Agent) reportOnce(ctx context.Context, currentInterval time.Duration) time.Duration {
	if ctx.Err() != nil {
		return currentInterval
	}
	_, ack, err := a.ReportOnce(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.logger.Printf("[dudu-probe] 指标上报失败: %v", err)
		}
		return currentInterval
	}
	if ctx.Err() != nil {
		return currentInterval
	}
	a.applyAck(ack)
	if ack != nil && ack.ReportIntervalSec > 0 {
		next := time.Duration(config.ClampInterval(ack.ReportIntervalSec)) * time.Second
		return next
	}
	return currentInterval
}
