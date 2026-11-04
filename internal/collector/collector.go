package collector

import (
	"context"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seakee/dudu-probe/internal/version"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gnet "github.com/shirou/gopsutil/v3/net"
)

// Collector 负责采集当前主机静态元信息与动态实时指标。
type Collector struct {
	mu              sync.Mutex
	hostRoot        string
	cachedMeta      *HostMeta
	lastMetaRefresh time.Time

	hasPrevSample   bool
	lastSampleTime  time.Time
	prevNetInBytes  uint64
	prevNetOutBytes uint64
	prevDiskRead    uint64
	prevDiskWrite   uint64
}

// New 创建并初始化采集器实例。
func New(hostRoot string) *Collector {
	if strings.TrimSpace(hostRoot) == "" {
		hostRoot = "/"
	}
	c := &Collector{
		hostRoot: hostRoot,
	}
	// 预热一次计数基线，使首次正式采集即可获得较准确的瞬时速率
	c.primeBaselines(context.Background())
	return c
}

// primeBaselines 初始化 CPU、网络与磁盘 IO 的基线计数器。
func (c *Collector) primeBaselines(ctx context.Context) {
	_, _ = cpu.PercentWithContext(ctx, 0, false)
	netIn, netOut := readNetTotals(ctx)
	diskR, diskW := readDiskIOTotals(ctx)
	c.lastSampleTime = time.Now()
	c.prevNetInBytes = netIn
	c.prevNetOutBytes = netOut
	c.prevDiskRead = diskR
	c.prevDiskWrite = diskW
	c.hasPrevSample = true
}

// CollectHostMeta 采集主机静态硬件与操作系统元信息（带 5 分钟内存缓存）。
func (c *Collector) CollectHostMeta(ctx context.Context, forceRefresh bool) *HostMeta {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !forceRefresh && c.cachedMeta != nil && time.Since(c.lastMetaRefresh) < 5*time.Minute {
		cp := *c.cachedMeta
		return &cp
	}

	meta := &HostMeta{
		OSName:       runtime.GOOS,
		Arch:         runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
		AgentVersion: version.Version,
		PrivateIP:    detectPrivateIP(),
	}

	if hInfo, err := host.InfoWithContext(ctx); err == nil && hInfo != nil {
		if hInfo.Platform != "" {
			meta.OSName = hInfo.Platform
		} else if hInfo.OS != "" {
			meta.OSName = hInfo.OS
		}
		meta.OSVersion = hInfo.PlatformVersion
		meta.KernelVersion = hInfo.KernelVersion
		if hInfo.KernelArch != "" {
			meta.Arch = hInfo.KernelArch
		}
		if hInfo.Hostname != "" {
			meta.Hostname = hInfo.Hostname
		}
		meta.BootTime = hInfo.BootTime
	}

	if meta.Hostname == "" {
		if hn, err := os.Hostname(); err == nil {
			meta.Hostname = hn
		}
	}

	if cpuInfos, err := cpu.InfoWithContext(ctx); err == nil && len(cpuInfos) > 0 {
		meta.CPUModel = strings.TrimSpace(cpuInfos[0].ModelName)
	}
	if logicalCores, err := cpu.CountsWithContext(ctx, true); err == nil && logicalCores > 0 {
		meta.CPUCores = logicalCores
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
		meta.MemTotal = vm.Total
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil && sw != nil {
		meta.SwapTotal = sw.Total
	}

	partitions, totalDisk, _ := collectDiskPartitions(ctx, c.hostRoot)
	if totalDisk > 0 {
		meta.DiskTotal = totalDisk
	} else if len(partitions) > 0 {
		for _, p := range partitions {
			meta.DiskTotal += p.Total
		}
	}

	c.cachedMeta = meta
	c.lastMetaRefresh = time.Now()
	cp := *meta
	return &cp
}

// CollectMetrics 采集当前时刻的实时性能、磁盘、网络与连接数指标。
func (c *Collector) CollectMetrics(ctx context.Context) (*MetricPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	payload := &MetricPayload{
		SampledAt: now.Unix(),
	}

	// 1. CPU 使用率
	if percents, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(percents) > 0 && percents[0] > 0 {
		payload.CPUUsage = round2(clampPercent(percents[0]))
	} else if percents, err := cpu.PercentWithContext(ctx, 150*time.Millisecond, false); err == nil && len(percents) > 0 && percents[0] > 0 {
		payload.CPUUsage = round2(clampPercent(percents[0]))
	} else if runtime.GOOS == "darwin" {
		payload.CPUUsage = round2(clampPercent(darwinCPUUsageFallback(ctx)))
	}

	// 2. 系统平均负载
	if avg, err := load.AvgWithContext(ctx); err == nil && avg != nil {
		payload.Load1 = round2(avg.Load1)
		payload.Load5 = round2(avg.Load5)
		payload.Load15 = round2(avg.Load15)
	}

	// 3. 物理内存与 Swap
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
		payload.MemTotal = vm.Total
		payload.MemUsed = vm.Used
		payload.MemAvailable = vm.Available
		payload.MemUsage = round2(clampPercent(vm.UsedPercent))
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil && sw != nil {
		payload.SwapTotal = sw.Total
		payload.SwapUsed = sw.Used
		payload.SwapUsage = round2(clampPercent(sw.UsedPercent))
	}

	// 4. 磁盘分区与使用率
	partitions, diskTotal, diskUsed := collectDiskPartitions(ctx, c.hostRoot)
	payload.DiskPartitions = partitions
	payload.DiskTotal = diskTotal
	payload.DiskUsed = diskUsed
	if diskTotal > 0 {
		payload.DiskUsage = round2(clampPercent(float64(diskUsed) * 100.0 / float64(diskTotal)))
	}

	// 5. 网络流量与磁盘 IO 速率（基于相邻采样窗口差值，若距上次采样不足 250ms 则短暂补齐窗口）
	if c.hasPrevSample {
		if wait := 250*time.Millisecond - time.Since(c.lastSampleTime); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	nowSample := time.Now()
	netIn, netOut := readNetTotals(ctx)
	diskRead, diskWrite := readDiskIOTotals(ctx)
	payload.NetInTotal = netIn
	payload.NetOutTotal = netOut

	if c.hasPrevSample {
		elapsed := nowSample.Sub(c.lastSampleTime).Seconds()
		if elapsed >= 0.1 {
			if netIn >= c.prevNetInBytes {
				payload.NetInSpeed = uint64(float64(netIn-c.prevNetInBytes) / elapsed)
			}
			if netOut >= c.prevNetOutBytes {
				payload.NetOutSpeed = uint64(float64(netOut-c.prevNetOutBytes) / elapsed)
			}
			if diskRead >= c.prevDiskRead {
				payload.DiskReadBytesSec = uint64(float64(diskRead-c.prevDiskRead) / elapsed)
			}
			if diskWrite >= c.prevDiskWrite {
				payload.DiskWriteBytesSec = uint64(float64(diskWrite-c.prevDiskWrite) / elapsed)
			}
		}
	}
	c.lastSampleTime = nowSample
	c.prevNetInBytes = netIn
	c.prevNetOutBytes = netOut
	c.prevDiskRead = diskRead
	c.prevDiskWrite = diskWrite
	c.hasPrevSample = true

	// 6. 运行时长与进程数
	if hInfo, err := host.InfoWithContext(ctx); err == nil && hInfo != nil {
		payload.UptimeSec = hInfo.Uptime
		payload.ProcessCount = int(hInfo.Procs)
	}

	// 7. TCP / UDP 连接数
	if tcpConns, err := gnet.ConnectionsWithContext(ctx, "tcp"); err == nil {
		payload.TCPConns = len(tcpConns)
	}
	if udpConns, err := gnet.ConnectionsWithContext(ctx, "udp"); err == nil {
		payload.UDPConns = len(udpConns)
	}

	return payload, nil
}

// collectDiskPartitions 获取所有真实磁盘分区及汇总容量。
func collectDiskPartitions(ctx context.Context, fallbackRoot string) ([]DiskPartitionStat, uint64, uint64) {
	parts, err := disk.PartitionsWithContext(ctx, false)
	var result []DiskPartitionStat
	var totalBytes, usedBytes uint64
	seenDevices := make(map[string]struct{})
	seenMounts := make(map[string]struct{})

	if err == nil {
		sort.SliceStable(parts, func(i, j int) bool {
			return len(parts[i].Mountpoint) < len(parts[j].Mountpoint)
		})
		for _, p := range parts {
			if ShouldIgnorePartition(p.Mountpoint, p.Fstype, p.Device) {
				continue
			}
			if _, ok := seenMounts[p.Mountpoint]; ok {
				continue
			}
			if p.Device != "" {
				if _, ok := seenDevices[p.Device]; ok {
					continue
				}
			}

			usage, uErr := disk.UsageWithContext(ctx, p.Mountpoint)
			if uErr != nil || usage == nil || usage.Total == 0 {
				continue
			}

			seenMounts[p.Mountpoint] = struct{}{}
			if p.Device != "" {
				seenDevices[p.Device] = struct{}{}
			}

			stat := DiskPartitionStat{
				Path:         p.Mountpoint,
				FSType:       p.Fstype,
				Total:        usage.Total,
				Used:         usage.Used,
				Free:         usage.Free,
				UsagePercent: round2(clampPercent(usage.UsedPercent)),
			}
			result = append(result, stat)
			totalBytes += usage.Total
			usedBytes += usage.Used
		}
	}

	// 若所有分区被过滤或容器内无挂载表，回退读取根路径
	if len(result) == 0 {
		root := fallbackRoot
		if root == "" {
			root = "/"
		}
		if usage, uErr := disk.UsageWithContext(ctx, root); uErr == nil && usage != nil && usage.Total > 0 {
			result = append(result, DiskPartitionStat{
				Path:         "/",
				FSType:       usage.Fstype,
				Total:        usage.Total,
				Used:         usage.Used,
				Free:         usage.Free,
				UsagePercent: round2(clampPercent(usage.UsedPercent)),
			})
			totalBytes = usage.Total
			usedBytes = usage.Used
		}
	}

	return result, totalBytes, usedBytes
}

// ShouldIgnorePartition 判断挂载点或文件系统是否为虚拟/临时分区。
func ShouldIgnorePartition(mountpoint, fstype, device string) bool {
	fs := strings.ToLower(strings.TrimSpace(fstype))
	ignoredFS := map[string]bool{
		"tmpfs":       true,
		"devtmpfs":    true,
		"devfs":       true,
		"squashfs":    true,
		"overlay":     true,
		"aufs":        true,
		"proc":        true,
		"sysfs":       true,
		"cgroup":      true,
		"cgroup2":     true,
		"nsfs":        true,
		"autofs":      true,
		"tracefs":     true,
		"debugfs":     true,
		"mqueue":      true,
		"hugetlbfs":   true,
		"fuse.lxcfs":  true,
		"iso9660":     true,
		"udf":         true,
		"ramfs":       true,
		"pstore":      true,
		"securityfs":  true,
		"configfs":    true,
		"fusectl":     true,
		"binfmt_misc": true,
	}
	if ignoredFS[fs] {
		return true
	}

	mp := strings.TrimSpace(mountpoint)
	ignoredPrefixes := []string{
		"/proc",
		"/sys",
		"/dev",
		"/run",
		"/etc",
		"/snap",
		"/var/lib/docker",
		"/var/lib/kubelet",
		"/System/Volumes/Data",
		"/System/Volumes/VM",
		"/System/Volumes/Preboot",
		"/System/Volumes/Update",
		"/System/Volumes/xarts",
		"/System/Volumes/iSCPreboot",
		"/System/Volumes/Hardware",
		"/private/var/vm",
	}
	for _, prefix := range ignoredPrefixes {
		if mp == prefix || strings.HasPrefix(mp, prefix+"/") {
			return true
		}
	}
	if strings.HasPrefix(device, "/dev/loop") {
		return true
	}
	return false
}

// ShouldIgnoreNetInterface 判断网卡是否为本地回环或容器虚拟网卡。
func ShouldIgnoreNetInterface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "lo" || n == "lo0" {
		return true
	}
	ignoredPrefixes := []string{
		"docker",
		"veth",
		"br-",
		"virbr",
		"cni",
		"flannel",
		"cali",
		"tunl",
		"kube",
		"utun",
		"awdl",
		"llw",
		"anpi",
		"gif",
		"stf",
		"ap",
	}
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// readNetTotals 汇总物理/主业务网卡的累计收发字节数。
func readNetTotals(ctx context.Context) (inBytes, outBytes uint64) {
	counters, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return 0, 0
	}
	for _, c := range counters {
		if ShouldIgnoreNetInterface(c.Name) {
			continue
		}
		inBytes += c.BytesRecv
		outBytes += c.BytesSent
	}
	return inBytes, outBytes
}

// readDiskIOTotals 汇总磁盘累计读写字节数。
func readDiskIOTotals(ctx context.Context) (readBytes, writeBytes uint64) {
	counters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return 0, 0
	}
	for name, c := range counters {
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		readBytes += c.ReadBytes
		writeBytes += c.WriteBytes
	}
	return readBytes, writeBytes
}

// detectPrivateIP 自动探测本机主要内网 IPv4 地址。
func detectPrivateIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			return addr.IP.String()
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ShouldIgnoreNetInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return ""
}

func clampPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// darwinCPUUsageFallback 在 macOS CGO_ENABLED=0 环境下通过 ps 汇总进程 CPU 占用率。
func darwinCPUUsageFallback(ctx context.Context) float64 {
	out, err := exec.CommandContext(ctx, "ps", "-A", "-o", "%cpu").Output()
	if err != nil {
		return 0
	}
	var sum float64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "%CPU" {
			continue
		}
		if v, err := strconv.ParseFloat(line, 64); err == nil && v > 0 {
			sum += v
		}
	}
	cores := runtime.NumCPU()
	if cores <= 0 {
		cores = 1
	}
	return sum / float64(cores)
}
