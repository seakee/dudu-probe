// Package main 提供 dudu-probe 探针二进制程序的命令行入口。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/seakee/dudu-probe/internal/agent"
	"github.com/seakee/dudu-probe/internal/client"
	"github.com/seakee/dudu-probe/internal/collector"
	"github.com/seakee/dudu-probe/internal/config"
	"github.com/seakee/dudu-probe/internal/version"
)

func main() {
	var (
		configPath  = flag.String("config", "", "配置文件路径 (默认读取 /etc/dudu-probe/config.json)")
		serverURL   = flag.String("server", "", "dudu 服务端地址 (例如 https://api.example.com)")
		nodeKey     = flag.String("key", "", "探针节点唯一标识 (node_key)")
		secret      = flag.String("secret", "", "探针节点通信密钥 (secret)")
		intervalSec = flag.Int("interval", 0, "指标上报间隔秒数 (默认 10)")
		timeoutSec  = flag.Int("timeout", 0, "HTTP 请求超时秒数 (默认 15)")
		insecureTLS = flag.Bool("insecure", false, "跳过 HTTPS TLS 证书校验")
		enableGzip  = flag.Bool("gzip", false, "启用上报请求 Gzip 压缩")
		onceMode    = flag.Bool("once", false, "仅执行单次采集与上报后退出")
		inspectMode = flag.Bool("inspect", false, "仅在本地采集一次指标并输出 JSON（不连接服务端）")
		showVersion = flag.Bool("version", false, "输出版本信息并退出")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Info())
		return
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	// 本地快速自检模式：无需服务端配置即可打印采集到的主机元信息与实时指标
	if *inspectMode {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		col := collector.New(os.Getenv("HOST_ROOT"))
		time.Sleep(200 * time.Millisecond)
		meta := col.CollectHostMeta(ctx, true)
		metrics, err := col.CollectMetrics(ctx)
		if err != nil {
			logger.Fatalf("采集本机指标失败: %v", err)
		}
		out, _ := json.MarshalIndent(&collector.ReportRequest{
			Host:    meta,
			Metrics: metrics,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("加载配置失败: %v", err)
	}

	// 命令行参数优先级高于配置文件与环境变量
	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *nodeKey != "" {
		cfg.NodeKey = *nodeKey
	}
	if *secret != "" {
		cfg.Secret = *secret
	}
	if *intervalSec > 0 {
		cfg.ReportIntervalSec = *intervalSec
	}
	if *timeoutSec > 0 {
		cfg.HTTPTimeoutSec = *timeoutSec
	}
	if *insecureTLS {
		cfg.InsecureTLS = true
	}
	if *enableGzip {
		cfg.EnableGzip = true
	}

	if err := cfg.NormalizeAndValidate(); err != nil {
		logger.Fatalf("配置校验失败: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	col := collector.New(cfg.HostRoot)
	cli := client.New(cfg)
	ag := agent.New(cfg, col, cli, logger)

	if *onceMode {
		meta := col.CollectHostMeta(ctx, true)
		if _, err := cli.Register(ctx, meta); err != nil {
			logger.Printf("[dudu-probe] 单次注册告警: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
		if _, _, err := ag.ReportOnce(ctx); err != nil {
			logger.Fatalf("[dudu-probe] 单次指标上报失败: %v", err)
		}
		logger.Printf("[dudu-probe] 单次采集上报成功")
		return
	}

	if err := ag.Run(ctx); err != nil {
		logger.Fatalf("[dudu-probe] 异常退出: %v", err)
	}
}
