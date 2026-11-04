// Package collector 提供服务器静态元信息与动态实时指标的跨平台采集能力。
package collector

// HostMeta 定义服务器静态硬件与操作系统元信息。
type HostMeta struct {
	OSName        string `json:"os_name"`        // 操作系统名称，如 ubuntu / alpine / darwin
	OSVersion     string `json:"os_version"`     // 操作系统版本
	KernelVersion string `json:"kernel_version"` // 内核版本
	Arch          string `json:"arch"`           // 系统架构，如 amd64 / arm64
	Hostname      string `json:"hostname"`       // 主机名
	CPUModel      string `json:"cpu_model"`      // CPU 型号名称
	CPUCores      int    `json:"cpu_cores"`      // 逻辑 CPU 核心数
	MemTotal      uint64 `json:"mem_total"`      // 物理内存总量（字节）
	SwapTotal     uint64 `json:"swap_total"`     // Swap 总量（字节）
	DiskTotal     uint64 `json:"disk_total"`     // 磁盘总容量（字节）
	PublicIP      string `json:"public_ip"`      // 公网 IP（可选，服务端也会从请求源 IP 补充）
	PrivateIP     string `json:"private_ip"`     // 内网 IP
	BootTime      uint64 `json:"boot_time"`      // 启动时间 Unix 时间戳（秒）
	AgentVersion  string `json:"agent_version"`  // 探针版本号
}

// DiskPartitionStat 定义单个磁盘分区的容量使用情况。
type DiskPartitionStat struct {
	Path         string  `json:"path"`          // 挂载路径
	FSType       string  `json:"fs_type"`       // 文件系统类型
	Total        uint64  `json:"total"`         // 总容量（字节）
	Used         uint64  `json:"used"`          // 已使用（字节）
	Free         uint64  `json:"free"`          // 可用容量（字节）
	UsagePercent float64 `json:"usage_percent"` // 使用率百分比
}

// MetricPayload 定义探针单次上报的实时指标数据。
type MetricPayload struct {
	SampledAt         int64               `json:"sampled_at"`          // 采样 Unix 时间戳（秒）
	CPUUsage          float64             `json:"cpu_usage"`           // CPU 使用率百分比 (0-100)
	Load1             float64             `json:"load1"`               // 1 分钟平均负载
	Load5             float64             `json:"load5"`               // 5 分钟平均负载
	Load15            float64             `json:"load15"`              // 15 分钟平均负载
	MemTotal          uint64              `json:"mem_total"`           // 内存总量（字节）
	MemUsed           uint64              `json:"mem_used"`            // 已用内存（字节）
	MemAvailable      uint64              `json:"mem_available"`       // 可用内存（字节）
	MemUsage          float64             `json:"mem_usage"`           // 内存使用率百分比 (0-100)
	SwapTotal         uint64              `json:"swap_total"`          // Swap 总量（字节）
	SwapUsed          uint64              `json:"swap_used"`           // 已用 Swap（字节）
	SwapUsage         float64             `json:"swap_usage"`          // Swap 使用率百分比 (0-100)
	DiskTotal         uint64              `json:"disk_total"`          // 磁盘总容量（字节）
	DiskUsed          uint64              `json:"disk_used"`           // 已用磁盘容量（字节）
	DiskUsage         float64             `json:"disk_usage"`          // 磁盘总使用率百分比 (0-100)
	DiskReadBytesSec  uint64              `json:"disk_read_bytes_sec"` // 磁盘读取速率（字节/秒）
	DiskWriteBytesSec uint64              `json:"disk_write_bytes_sec"`// 磁盘写入速率（字节/秒）
	NetInSpeed        uint64              `json:"net_in_speed"`        // 入站实时网速（字节/秒）
	NetOutSpeed       uint64              `json:"net_out_speed"`       // 出站实时网速（字节/秒）
	NetInTotal        uint64              `json:"net_in_total"`        // 累计入站总流量（字节）
	NetOutTotal       uint64              `json:"net_out_total"`       // 累计出站总流量（字节）
	TCPConns          int                 `json:"tcp_conns"`           // 活跃 TCP 连接数
	UDPConns          int                 `json:"udp_conns"`           // 活跃 UDP 连接数
	ProcessCount      int                 `json:"process_count"`       // 运行进程数
	UptimeSec         uint64              `json:"uptime_sec"`          // 系统运行时长（秒）
	DiskPartitions    []DiskPartitionStat `json:"disk_partitions"`     // 各磁盘挂载点明细
}

// ReportRequest 定义上报给服务端的完整请求报文。
type ReportRequest struct {
	Host    *HostMeta      `json:"host,omitempty"` // 附带主机静态元信息，便于服务端自愈同步
	Metrics *MetricPayload `json:"metrics"`        // 实时性能指标
}
