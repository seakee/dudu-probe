package collector

import (
	"context"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/shirou/gopsutil/v3/process"
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

	prevProcCPU  map[int32]float64
	prevProcTime time.Time

	pingMu      sync.RWMutex
	pingTargets []PingTarget
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

	privIP, pubIP := detectHostIPs()
	if !forceRefresh && c.cachedMeta != nil && time.Since(c.lastMetaRefresh) < 5*time.Minute {
		cp := *c.cachedMeta
		if privIP != "" {
			cp.PrivateIP = privIP
		}
		if pubIP != "" {
			cp.PublicIP = pubIP
		}
		return &cp
	}

	meta := &HostMeta{
		OSName:       runtime.GOOS,
		Arch:         runtime.GOARCH,
		CPUCores:     runtime.NumCPU(),
		AgentVersion: version.Version,
		PrivateIP:    privIP,
		PublicIP:     pubIP,
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

	// 8. 硬件温度传感器采集
	cpuTemp, temps := collectTemperatures(ctx, c.hostRoot)
	payload.CPUTemp = cpuTemp
	payload.Temperatures = temps

	// 9. Top 5 高占用进程快照
	payload.TopProcesses = c.collectTopProcesses(ctx, payload.MemTotal)

	// 10. 多目标并发 TCP Ping 测速
	payload.PingResults = c.collectPingResults(ctx)

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
		hasRootMount := false
		for _, p := range parts {
			if p.Mountpoint == "/" {
				hasRootMount = true
				break
			}
		}
		if !hasRootMount {
			if allParts, allErr := disk.PartitionsWithContext(ctx, true); allErr == nil {
				for _, ap := range allParts {
					fs := strings.ToLower(strings.TrimSpace(ap.Fstype))
					if ap.Mountpoint == "/" && (fs == "overlay" || fs == "overlayfs") {
						parts = append(parts, ap)
						break
					}
				}
			}
		}
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
	mp := strings.TrimSpace(mountpoint)
	fs := strings.ToLower(strings.TrimSpace(fstype))
	if (fs == "overlay" || fs == "overlayfs") && mp == "/" {
		return false
	}
	ignoredFS := map[string]bool{
		"tmpfs":       true,
		"devtmpfs":    true,
		"devfs":       true,
		"squashfs":    true,
		"overlay":     true,
		"overlayfs":   true,
		"sysfs":       true,
		"cgroup":      true,
		"cgroup2":     true,
		"nsfs":        true,
		"autofs":      true,
		"tracefs":     true,
		"debugfs":     true,
		"mqueue":      true,
		"hugetlbfs":       true,
		"fuse":            true,
		"fuse.lxcfs":      true,
		"fuse.hdsfusemnt": true,
		"cmfs":            true,
		"iso9660":         true,
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
		"/mnt/boot_config",
		"/mnt/HDA_ROOT",
		"/mnt/ext",
		"/share/external/.cm",
	}
	for _, prefix := range ignoredPrefixes {
		if mp == prefix || strings.HasPrefix(mp, prefix+"/") {
			return true
		}
	}
	if strings.Contains(mp, "/.qpkg/") {
		return true
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

// detectHostIPs 自动探测并区分本机主要内网 IPv4 (RFC1918/CGNAT) 与网卡/拨号公网 IPv4。
//
// 返回值:
//
//	privateIP: 优先取默认路由出口或 br-lan 上的私网/CGNAT 地址
//	publicIP:  优先取默认路由出口或物理网卡上的全局单播公网地址
func detectHostIPs() (privateIP, publicIP string) {
	hardPrivate := false

	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			if ipv4 := addr.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() {
				switch {
				case ipv4.IsPrivate():
					privateIP = ipv4.String()
					hardPrivate = true
				case isPrivateOrCarrierNAT(ipv4):
					// TUN/代理网卡常见 198.18.0.0/15、100.64.0.0/10，先记录但允许被真实局域网地址覆盖
					privateIP = ipv4.String()
				case ipv4.IsGlobalUnicast():
					publicIP = ipv4.String()
				}
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return privateIP, publicIP
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// br-lan 承载 OpenWrt 等软路由的局域网网关地址，需显式保留
		isLanBridge := strings.EqualFold(strings.TrimSpace(iface.Name), "br-lan")
		if !isLanBridge && ShouldIgnoreNetInterface(iface.Name) {
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
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			switch {
			case ipv4.IsPrivate():
				// 真实局域网地址优先级最高；br-lan 网关地址覆盖同网段其他网卡
				if !hardPrivate || isLanBridge {
					privateIP = ipv4.String()
					hardPrivate = true
				}
			case isPrivateOrCarrierNAT(ipv4):
				if privateIP == "" {
					privateIP = ipv4.String()
				}
			case ipv4.IsGlobalUnicast() && publicIP == "":
				publicIP = ipv4.String()
			}
		}
	}
	return privateIP, publicIP
}

// isPrivateOrCarrierNAT 判断 IPv4 是否属于私网、回环、链路本地、运营商级 NAT 或基准测试网段。
func isPrivateOrCarrierNAT(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		// RFC 6598 运营商级 NAT (100.64.0.0/10)
		if ipv4[0] == 100 && ipv4[1] >= 64 && ipv4[1] <= 127 {
			return true
		}
		// RFC 2544 基准测试保留段 (198.18.0.0/15)，常见于代理软件 TUN 网卡
		if ipv4[0] == 198 && (ipv4[1] == 18 || ipv4[1] == 19) {
			return true
		}
	}
	return false
}

// collectTemperatures 采集主机硬件温度传感器读数。
//
// 参数:
//   ctx: 上下文对象
//   hostRoot: 容器挂载的宿主机根目录
//
// 返回值:
//   float64: 主 CPU 温度（摄氏度），无传感器时为 0
//   []SensorTemp: 最多 8 条传感器明细
func collectTemperatures(ctx context.Context, hostRoot string) (float64, []SensorTemp) {
	var list []SensorTemp
	seen := make(map[string]bool)

	if stats, err := host.SensorsTemperaturesWithContext(ctx); err == nil {
		for _, st := range stats {
			if st.Temperature <= 0 || st.Temperature >= 150 || math.IsNaN(st.Temperature) {
				continue
			}
			key := strings.TrimSpace(st.SensorKey)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			list = append(list, SensorTemp{
				Key:         key,
				Temperature: round2(st.Temperature),
			})
		}
	}

	// Linux sysfs 兜底读取（/sys/class/thermal/thermal_zone*），覆盖 OpenWrt 等无 hwmon 的固件
	if len(list) == 0 && runtime.GOOS == "linux" {
		sysBase := "/sys/class/thermal"
		if hostRoot != "" && hostRoot != "/" {
			alt := filepath.Join(hostRoot, "sys/class/thermal")
			if _, err := os.Stat(alt); err == nil {
				sysBase = alt
			}
		}
		if matches, err := filepath.Glob(filepath.Join(sysBase, "thermal_zone*")); err == nil {
			for _, zoneDir := range matches {
				rawTemp, err := os.ReadFile(filepath.Join(zoneDir, "temp"))
				if err != nil {
					continue
				}
				val, err := strconv.ParseFloat(strings.TrimSpace(string(rawTemp)), 64)
				if err != nil || val <= 0 {
					continue
				}
				// 内核以毫摄氏度上报
				if val > 200 {
					val = val / 1000.0
				}
				if val <= 0 || val >= 150 {
					continue
				}
				zoneKey := filepath.Base(zoneDir)
				if rawType, tErr := os.ReadFile(filepath.Join(zoneDir, "type")); tErr == nil {
					if t := strings.TrimSpace(string(rawType)); t != "" {
						zoneKey = t
					}
				}
				if seen[zoneKey] {
					continue
				}
				seen[zoneKey] = true
				list = append(list, SensorTemp{
					Key:         zoneKey,
					Temperature: round2(val),
				})
			}
		}
	}

	if len(list) == 0 {
		return 0, nil
	}

	var cpuTemp, maxTemp float64
	for _, item := range list {
		if item.Temperature > maxTemp {
			maxTemp = item.Temperature
		}
		k := strings.ToLower(item.Key)
		if strings.Contains(k, "cpu") || strings.Contains(k, "package") ||
			strings.Contains(k, "coretemp") || strings.Contains(k, "k10temp") ||
			strings.Contains(k, "soc") || strings.Contains(k, "x86_pkg") {
			if item.Temperature > cpuTemp {
				cpuTemp = item.Temperature
			}
		}
	}
	if cpuTemp == 0 {
		cpuTemp = maxTemp
	}
	if len(list) > 8 {
		list = list[:8]
	}
	return round2(cpuTemp), list
}

// collectTopProcesses 采集当前 CPU/内存综合占用最高的前 5 个进程快照。
//
// 参数:
//   ctx: 上下文对象
//   memTotal: 物理内存总量（字节），用于换算进程内存占比
//
// 返回值:
//   []ProcessStat: 最多 5 条进程快照，采集失败时返回 nil
func (c *Collector) collectTopProcesses(ctx context.Context, memTotal uint64) []ProcessStat {
	now := time.Now()
	elapsed := now.Sub(c.prevProcTime).Seconds()

	// macOS 在 CGO_ENABLED=0 下 gopsutil 无法读取进程 CPU 时间，直接走 ps 兜底
	if runtime.GOOS == "darwin" {
		return collectTopProcessesViaPS(ctx)
	}

	procs, err := process.ProcessesWithContext(ctx)
	if err != nil || len(procs) == 0 {
		return collectTopProcessesViaPS(ctx)
	}

	cores := float64(runtime.NumCPU())
	if cores < 1 {
		cores = 1
	}
	nextCPU := make(map[int32]float64, len(procs))
	candidates := make([]ProcessStat, 0, 64)

	for _, p := range procs {
		if p == nil || p.Pid <= 0 {
			continue
		}
		var rawCPUPct float64
		if times, tErr := p.TimesWithContext(ctx); tErr == nil && times != nil {
			totalSec := times.User + times.System
			nextCPU[p.Pid] = totalSec
			if c.prevProcCPU != nil && elapsed >= 0.2 {
				if prevSec, ok := c.prevProcCPU[p.Pid]; ok && totalSec >= prevSec {
					rawCPUPct = ((totalSec - prevSec) / elapsed) * 100.0
				}
			}
		}
		var rss uint64
		if memInfo, mErr := p.MemoryInfoWithContext(ctx); mErr == nil && memInfo != nil {
			rss = memInfo.RSS
		}
		// 跳过明显空闲的进程，减少后续 Name 系统调用
		if rawCPUPct < 0.1 && rss < (4<<20) {
			continue
		}
		name, nErr := p.NameWithContext(ctx)
		if nErr != nil {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var memPct float64
		if memTotal > 0 && rss > 0 {
			memPct = float64(rss) * 100.0 / float64(memTotal)
		}
		candidates = append(candidates, ProcessStat{
			PID:        p.Pid,
			Name:       name,
			CPUPercent: round2(clampPercent(rawCPUPct / cores)),
			MemPercent: round2(clampPercent(memPct)),
			MemRSS:     rss,
		})
	}

	c.prevProcCPU = nextCPU
	c.prevProcTime = now

	if len(candidates) == 0 {
		return collectTopProcessesViaPS(ctx)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if math.Abs(candidates[i].CPUPercent-candidates[j].CPUPercent) > 0.5 {
			return candidates[i].CPUPercent > candidates[j].CPUPercent
		}
		return candidates[i].MemRSS > candidates[j].MemRSS
	})
	if len(candidates) > 5 {
		candidates = candidates[:5]
	}
	return candidates
}

// collectTopProcessesViaPS 通过 ps 命令兜底采集 Top 5 进程（macOS 及 gopsutil 不可用时）。
func collectTopProcessesViaPS(ctx context.Context) []ProcessStat {
	out, err := exec.CommandContext(ctx, "ps", "-A", "-o", "pid,%cpu,%mem,rss,comm").Output()
	if err != nil {
		return nil
	}
	cores := float64(runtime.NumCPU())
	if cores < 1 {
		cores = 1
	}
	lines := strings.Split(string(out), "\n")
	list := make([]ProcessStat, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || fields[0] == "PID" {
			continue
		}
		pid, pErr := strconv.ParseInt(fields[0], 10, 32)
		if pErr != nil || pid <= 0 {
			continue
		}
		cpuPct, _ := strconv.ParseFloat(fields[1], 64)
		memPct, _ := strconv.ParseFloat(fields[2], 64)
		rssKB, _ := strconv.ParseUint(fields[3], 10, 64)
		name := filepath.Base(strings.Join(fields[4:], " "))
		if name == "" {
			continue
		}
		list = append(list, ProcessStat{
			PID:        int32(pid),
			Name:       name,
			CPUPercent: round2(clampPercent(cpuPct / cores)),
			MemPercent: round2(clampPercent(memPct)),
			MemRSS:     rssKB * 1024,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		if math.Abs(list[i].CPUPercent-list[j].CPUPercent) > 0.5 {
			return list[i].CPUPercent > list[j].CPUPercent
		}
		return list[i].MemRSS > list[j].MemRSS
	})
	if len(list) > 5 {
		list = list[:5]
	}
	return list
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
