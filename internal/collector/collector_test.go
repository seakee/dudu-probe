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
