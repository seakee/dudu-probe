package collector

import (
	"context"
	"testing"
	"time"
)

func TestFilterRules(t *testing.T) {
	if !ShouldIgnorePartition("/proc", "proc", "proc") {
		t.Fatal("expected /proc to be ignored")
	}
	if !ShouldIgnorePartition("/var/lib/docker/overlay2/abc", "overlay", "overlay") {
		t.Fatal("expected docker overlay partition to be ignored")
	}
	if !ShouldIgnorePartition("/opt/docker", "overlay", "overlayfs:/overlay") {
		t.Fatal("expected non-root overlay partition to be ignored")
	}
	if ShouldIgnorePartition("/", "overlay", "overlayfs:/overlay") {
		t.Fatal("expected OpenWrt root overlay partition (/) not to be ignored")
	}
	if !ShouldIgnorePartition("/etc/hosts", "ext4", "/dev/vda1") {
		t.Fatal("expected /etc/hosts bind mount to be ignored")
	}
	if ShouldIgnorePartition("/", "ext4", "/dev/sda1") {
		t.Fatal("expected root ext4 partition not to be ignored")
	}
	if !ShouldIgnorePartition("/mnt/HDA_ROOT", "ext3", "/dev/md9") || !ShouldIgnorePartition("/mnt/ext", "ext4", "/dev/md13") {
		t.Fatal("expected QNAP QTS system firmware partitions to be ignored")
	}
	if !ShouldIgnorePartition("/share/CACHEDEV1_DATA/.qpkg/MediaSignPlayer/CodexPackExt/share", "fuse.hdsfusemnt", "hdsfusemnt") {
		t.Fatal("expected QNAP QTS .qpkg fuse mount to be ignored")
	}
	if ShouldIgnorePartition("/share/CACHEDEV1_DATA", "ext4", "/dev/mapper/cachedev1") {
		t.Fatal("expected QNAP QTS CACHEDEV1_DATA data volume not to be ignored")
	}

	if !ShouldIgnoreNetInterface("lo") || !ShouldIgnoreNetInterface("docker0") || !ShouldIgnoreNetInterface("veth1a2b") {
		t.Fatal("expected virtual/loopback interfaces to be ignored")
	}
	if ShouldIgnoreNetInterface("eth0") || ShouldIgnoreNetInterface("en0") {
		t.Fatal("expected physical interfaces not to be ignored")
	}
}

func TestCollectHostMetaAndMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := New("/")
	meta := col.CollectHostMeta(ctx, true)
	if meta == nil {
		t.Fatal("expected non-nil HostMeta")
	}
	if meta.OSName == "" || meta.Arch == "" || meta.CPUCores <= 0 {
		t.Fatalf("unexpected HostMeta: %+v", meta)
	}

	time.Sleep(150 * time.Millisecond)
	metrics, err := col.CollectMetrics(ctx)
	if err != nil {
		t.Fatalf("CollectMetrics failed: %v", err)
	}
	if metrics.SampledAt <= 0 {
		t.Fatalf("expected positive SampledAt, got %d", metrics.SampledAt)
	}
	if metrics.CPUUsage < 0 || metrics.CPUUsage > 100 {
		t.Fatalf("invalid CPUUsage: %f", metrics.CPUUsage)
	}
	if metrics.MemTotal == 0 {
		t.Fatalf("expected non-zero MemTotal")
	}
}

func TestCollectHostMetaAndMetricsCancellation(t *testing.T) {
	col := New("/")

	// 1. 已取消上下文采集 HostMeta 不得缓存残缺数据
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	metaCanceled := col.CollectHostMeta(canceledCtx, true)
	if metaCanceled == nil || metaCanceled.OSName == "" {
		t.Fatalf("expected minimal fallback HostMeta, got %+v", metaCanceled)
	}
	col.mu.Lock()
	cachedAfterCancel := col.cachedMeta
	lastRefreshAfterCancel := col.lastMetaRefresh
	col.mu.Unlock()
	if cachedAfterCancel != nil || !lastRefreshAfterCancel.IsZero() {
		t.Fatalf("expected canceled CollectHostMeta not to populate cache, got cached=%+v refresh=%v", cachedAfterCancel, lastRefreshAfterCancel)
	}

	// 2. 健康上下文采集并缓存后，再次用过期上下文调用必须保留既有完整缓存
	validCtx, cancelValid := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelValid()
	metaValid := col.CollectHostMeta(validCtx, true)
	if metaValid == nil || metaValid.MemTotal == 0 {
		t.Fatalf("expected full HostMeta with MemTotal > 0, got %+v", metaValid)
	}
	expiredCtx, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	metaAfterExpiry := col.CollectHostMeta(expiredCtx, true)
	if metaAfterExpiry == nil || metaAfterExpiry.MemTotal != metaValid.MemTotal {
		t.Fatalf("expected existing full cache preserved on expired context, got %+v vs %+v", metaAfterExpiry, metaValid)
	}

	// 3. CollectMetrics 在已取消或过期上下文中返回错误且不污染采样基线
	col.mu.Lock()
	col.hasPrevSample = false
	prevSampleTime := col.lastSampleTime
	col.mu.Unlock()
	if _, err := col.CollectMetrics(canceledCtx); err == nil {
		t.Fatal("expected error from CollectMetrics on canceled context")
	}
	col.mu.Lock()
	hasPrev := col.hasPrevSample
	afterSampleTime := col.lastSampleTime
	col.mu.Unlock()
	if hasPrev || !afterSampleTime.Equal(prevSampleTime) {
		t.Fatalf("expected canceled CollectMetrics not to commit sample baseline: hasPrev=%v time=%v vs %v", hasPrev, afterSampleTime, prevSampleTime)
	}
}
