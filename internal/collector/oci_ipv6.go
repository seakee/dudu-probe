package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seakee/dudu-probe/internal/version"
)

const (
	ociIMDSVNICsURL       = "http://169.254.169.254/opc/v2/vnics/"
	ociIMDSAuthHeader     = "Authorization"
	ociIMDSAuthValue      = "Bearer Oracle"
	ociIMDSTimeout        = 2 * time.Second
	ociIPv6SampleInterval = 60 * time.Second
	ociUnconfirmedBackoff = 30 * time.Minute
	ociUnconfirmedMaxFast = 3
	ociIMDSMaxBodyBytes   = 1 << 20
	ociMaxAssignedAddrs   = 128
	ociDMIChassisAssetTag = "OracleCloud.com"
	procIfInet6Path       = "/proc/net/if_inet6"

	// Linux /proc/net/if_inet6 地址作用域与标志位（linux/if_addr.h & net/ipv6/addrconf.c）。
	linuxIPv6ScopeGlobal uint8  = 0x00
	linuxIFAFTemporary   uint32 = 0x01 // IFA_F_TEMPORARY / IFA_F_SECONDARY
	linuxIFAFOptimistic  uint32 = 0x04 // IFA_F_OPTIMISTIC
	linuxIFAFDADFailed   uint32 = 0x08 // IFA_F_DADFAILED
	linuxIFAFDeprecated  uint32 = 0x20 // IFA_F_DEPRECATED
	linuxIFAFTentative   uint32 = 0x40 // IFA_F_TENTATIVE
)

var nonPublicIPv6Prefixes = [...]netip.Prefix{
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var nonOCIDMIMarkers = []string{
	"amazon ec2",
	"google compute engine",
	"microsoft corporation",
	"alibaba cloud",
	"tencent cloud",
	"digitalocean",
	"vultr",
	"hetzner",
	"linode",
	"scaleway",
	"vmware",
	"virtualbox",
	"innotek",
	"parallels",
	"qnap",
	"synology",
}

type dmiPlatform uint8

const (
	dmiUnknown dmiPlatform = iota
	dmiOCI
	dmiNonOCI
)

type ociVNIC struct {
	VNICID        string   `json:"vnicId"`
	PrivateIP     string   `json:"privateIp"`
	MACAddr       string   `json:"macAddr"`
	NICIndex      *int     `json:"nicIndex"`
	IsPrimary     *bool    `json:"isPrimary"`
	IPv6Addresses []string `json:"ipv6Addresses"`
}

type localIPv6Addr struct {
	Addr  netip.Addr
	Scope uint8
	Flags uint32
}

type localInterface struct {
	Index        int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	NoCarrier    bool
	IPv6Addrs    []localIPv6Addr
}

type procIfInet6Entry struct {
	Addr    netip.Addr
	IfIndex int
	Scope   uint8
	Flags   uint32
	IfName  string
}

// ociIPv6Observer 负责执行 OCI IMDSv2 VNIC 查询与本机 Linux 网卡 IPv6 交叉验证。
type ociIPv6Observer struct {
	hostRoot       string
	imdsURL        string
	imdsTimeout    time.Duration
	sampleInterval time.Duration
	httpClient     *http.Client

	goos         string
	now          func() time.Time
	dmiDetectFn  func() dmiPlatform
	interfacesFn func() ([]localInterface, error)

	sampleMu            sync.Mutex
	mu                  sync.Mutex
	dmiChecked          bool
	dmiStatus           dmiPlatform
	confirmedOCI        bool
	unconfirmedFailures int
	hasSampled          bool
	lastSampleAt        time.Time
	nextSampleAt        time.Time
	lastSelected        netip.Addr
	cached              *IPv6Observation
}

func newOCIIMDSClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = ociIMDSTimeout
	}
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	tr := &http.Transport{
		Proxy:                 nil, // 显式禁用环境代理，直连链路本地 IMDSv2
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 0,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newOCIIPv6Observer(hostRoot string) *ociIPv6Observer {
	return &ociIPv6Observer{
		hostRoot:       hostRoot,
		imdsURL:        ociIMDSVNICsURL,
		imdsTimeout:    ociIMDSTimeout,
		sampleInterval: ociIPv6SampleInterval,
		httpClient:     newOCIIMDSClient(ociIMDSTimeout),
		goos:           runtime.GOOS,
		now:            time.Now,
	}
}

func (o *ociIPv6Observer) isLinux() bool {
	goos := o.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	return goos == "linux"
}

func (o *ociIPv6Observer) currentIntervalLocked() time.Duration {
	if o.confirmedOCI || o.dmiStatus == dmiOCI {
		return o.sampleInterval
	}
	if o.unconfirmedFailures >= ociUnconfirmedMaxFast {
		return ociUnconfirmedBackoff
	}
	return o.sampleInterval
}

func (o *ociIPv6Observer) detectDMILocked() dmiPlatform {
	if o.dmiChecked {
		return o.dmiStatus
	}
	if o.dmiDetectFn != nil {
		o.dmiStatus = o.dmiDetectFn()
	} else {
		o.dmiStatus = detectLinuxDMI(o.hostRoot)
	}
	o.dmiChecked = true
	return o.dmiStatus
}

// Observe 按 60 秒周期采样 OCI IPv6 状态，非 Linux 或明确非 OCI 环境安全跳过。
func (o *ociIPv6Observer) Observe(ctx context.Context, forceRefresh bool) *IPv6Observation {
	if o == nil || !o.isLinux() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		o.mu.Lock()
		cp := cloneIPv6Observation(o.cached)
		o.mu.Unlock()
		return cp
	}

	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()

	if ctx.Err() != nil {
		o.mu.Lock()
		cp := cloneIPv6Observation(o.cached)
		o.mu.Unlock()
		return cp
	}

	o.mu.Lock()
	sampleStart := o.now()
	if !forceRefresh && o.hasSampled && sampleStart.Before(o.nextSampleAt) {
		cp := cloneIPv6Observation(o.cached)
		o.mu.Unlock()
		return cp
	}
	dmi := o.detectDMILocked()
	if dmi == dmiNonOCI && !o.confirmedOCI {
		o.lastSampleAt = sampleStart
		o.nextSampleAt = sampleStart.Add(o.sampleInterval)
		o.hasSampled = true
		o.cached = nil
		o.mu.Unlock()
		return nil
	}
	if dmi == dmiOCI {
		o.confirmedOCI = true
	}
	confirmedOCI := o.confirmedOCI
	prevAddr := o.lastSelected
	o.mu.Unlock()

	if ctx.Err() != nil {
		o.mu.Lock()
		cp := cloneIPv6Observation(o.cached)
		o.mu.Unlock()
		return cp
	}

	obs, sampleConfirmedOCI, newSelected := o.sampleOnce(ctx, confirmedOCI, prevAddr)
	if ctx.Err() != nil {
		o.mu.Lock()
		cp := cloneIPv6Observation(o.cached)
		o.mu.Unlock()
		return cp
	}

	o.mu.Lock()
	if sampleConfirmedOCI {
		o.confirmedOCI = true
		o.unconfirmedFailures = 0
	} else if !o.confirmedOCI {
		o.unconfirmedFailures++
	}
	if newSelected.IsValid() {
		o.lastSelected = newSelected
	} else if obs != nil && obs.State == IPv6ObservationStateObserved {
		o.lastSelected = netip.Addr{}
	}
	o.lastSampleAt = sampleStart
	interval := o.currentIntervalLocked()
	if forceRefresh || !o.hasSampled || o.nextSampleAt.IsZero() || interval > o.sampleInterval {
		o.nextSampleAt = sampleStart.Add(interval)
	} else if !sampleStart.Before(o.nextSampleAt) {
		steps := sampleStart.Sub(o.nextSampleAt)/interval + 1
		o.nextSampleAt = o.nextSampleAt.Add(steps * interval)
	} else {
		o.nextSampleAt = sampleStart.Add(interval)
	}
	o.hasSampled = true
	o.cached = cloneIPv6Observation(obs)
	cp := cloneIPv6Observation(obs)
	o.mu.Unlock()
	return cp
}

func (o *ociIPv6Observer) sampleOnce(ctx context.Context, confirmedOCI bool, prevAddr netip.Addr) (*IPv6Observation, bool, netip.Addr) {
	body, _, sourceIP, err := o.fetchVNICs(ctx)
	if err != nil {
		if !confirmedOCI {
			return nil, false, netip.Addr{}
		}
		return &IPv6Observation{
			State:      IPv6ObservationStateUnavailable,
			ObservedAt: o.now().Unix(),
		}, false, netip.Addr{}
	}
	if ctx.Err() != nil {
		return nil, false, netip.Addr{}
	}

	vnicMAC, assigned, err := parsePrimaryVNICObservation(body, sourceIP)
	if err != nil {
		if !confirmedOCI {
			return nil, false, netip.Addr{}
		}
		return &IPv6Observation{
			State:      IPv6ObservationStateUnavailable,
			ObservedAt: o.now().Unix(),
		}, false, netip.Addr{}
	}

	observedAt := o.now().Unix()
	assignedStrs := make([]string, len(assigned))
	for i, addr := range assigned {
		assignedStrs[i] = addr.String()
	}

	if len(assigned) == 0 {
		return &IPv6Observation{
			State:      IPv6ObservationStateObserved,
			ObservedAt: observedAt,
			Assigned:   assignedStrs,
		}, true, netip.Addr{}
	}

	if ctx.Err() != nil {
		return nil, false, netip.Addr{}
	}

	ifaces, err := o.readInterfaces()
	if err != nil {
		return &IPv6Observation{
			State:      IPv6ObservationStateUnavailable,
			ObservedAt: observedAt,
		}, true, netip.Addr{}
	}

	selected, ok := selectUsableAssignedIPv6(vnicMAC, assigned, ifaces, prevAddr)
	obs := &IPv6Observation{
		State:      IPv6ObservationStateObserved,
		ObservedAt: observedAt,
		Assigned:   assignedStrs,
	}
	if ok {
		obs.Address = selected.String()
	}
	return obs, true, selected
}

func (o *ociIPv6Observer) fetchVNICs(ctx context.Context) ([]byte, int, netip.Addr, error) {
	timeout := o.imdsTimeout
	if timeout <= 0 {
		timeout = ociIMDSTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var localAddrMu sync.Mutex
	var sourceIP netip.Addr
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if addr, ok := ipv4FromNetAddr(info.Conn.LocalAddr()); ok {
				localAddrMu.Lock()
				sourceIP = addr
				localAddrMu.Unlock()
			}
		},
	}
	traceCtx := httptrace.WithClientTrace(reqCtx, trace)

	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, o.imdsURL, nil)
	if err != nil {
		return nil, 0, netip.Addr{}, err
	}
	req.Header.Set(ociIMDSAuthHeader, ociIMDSAuthValue)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dudu-probe/"+version.Version)

	client := o.httpClient
	if client == nil {
		client = newOCIIMDSClient(timeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, netip.Addr{}, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, ociIMDSMaxBodyBytes+1))
	if readErr != nil {
		return nil, resp.StatusCode, netip.Addr{}, readErr
	}
	if len(body) > ociIMDSMaxBodyBytes {
		return nil, resp.StatusCode, netip.Addr{}, fmt.Errorf("OCI IMDS 响应体超过限制 (%d bytes)", ociIMDSMaxBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, netip.Addr{}, fmt.Errorf("OCI IMDS 返回非 200 状态码: %d", resp.StatusCode)
	}

	localAddrMu.Lock()
	capturedSource := sourceIP
	localAddrMu.Unlock()
	return body, resp.StatusCode, capturedSource, nil
}

func (o *ociIPv6Observer) readInterfaces() ([]localInterface, error) {
	if o.interfacesFn != nil {
		return o.interfacesFn()
	}
	return readLinuxInterfaces(
		o.hostRoot,
		net.Interfaces,
		func(iface net.Interface) ([]net.Addr, error) {
			return iface.Addrs()
		},
		procIfInet6Path,
	)
}

func ipv4FromNetAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	var ip net.IP
	switch v := addr.(type) {
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip != nil {
		if parsed, ok := netip.AddrFromSlice(ip); ok {
			parsed = parsed.Unmap()
			if parsed.IsValid() && parsed.Is4() && !parsed.IsUnspecified() {
				return parsed, true
			}
		}
		return netip.Addr{}, false
	}
	raw := strings.TrimSpace(addr.String())
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		a := ap.Addr().Unmap()
		if a.IsValid() && a.Is4() && !a.IsUnspecified() {
			return a, true
		}
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		a = a.Unmap()
		if a.IsValid() && a.Is4() && !a.IsUnspecified() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func parsePrimaryVNICObservation(rawBody []byte, sourceIP netip.Addr) (net.HardwareAddr, []netip.Addr, error) {
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		return nil, nil, errors.New("OCI IMDS 返回空响应")
	}

	var vnics []*ociVNIC
	if err := json.Unmarshal(trimmed, &vnics); err != nil {
		return nil, nil, err
	}
	primary, err := selectPrimaryVNIC(vnics, sourceIP)
	if err != nil {
		return nil, nil, err
	}

	macStr := strings.TrimSpace(primary.MACAddr)
	if macStr == "" {
		return nil, nil, errors.New("OCI 主 VNIC 缺少 macAddr")
	}
	mac, err := net.ParseMAC(macStr)
	if err != nil || len(mac) == 0 {
		return nil, nil, fmt.Errorf("OCI 主 VNIC macAddr 非法: %q", primary.MACAddr)
	}

	if len(primary.IPv6Addresses) > ociMaxAssignedAddrs {
		return nil, nil, fmt.Errorf("OCI 主 VNIC ipv6Addresses 数量超出上限: %d", len(primary.IPv6Addresses))
	}

	seen := make(map[netip.Addr]struct{}, len(primary.IPv6Addresses))
	assigned := make([]netip.Addr, 0, len(primary.IPv6Addresses))
	for _, raw := range primary.IPv6Addresses {
		s := strings.TrimSpace(raw)
		if s == "" {
			return nil, nil, errors.New("OCI 主 VNIC ipv6Addresses 包含空地址")
		}
		addr, parseErr := netip.ParseAddr(s)
		if parseErr != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
			return nil, nil, fmt.Errorf("OCI 主 VNIC ipv6Addresses 包含非法 IPv6: %q", raw)
		}
		if !isPublicIPv6(addr) {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		assigned = append(assigned, addr)
	}
	slices.SortFunc(assigned, netip.Addr.Compare)
	return mac, assigned, nil
}

func selectPrimaryVNIC(vnics []*ociVNIC, sourceIP netip.Addr) (*ociVNIC, error) {
	if len(vnics) == 0 {
		return nil, errors.New("OCI IMDS 未包含有效 VNIC")
	}

	parsedPrivIPs := make([]netip.Addr, len(vnics))
	for i, v := range vnics {
		if v == nil {
			return nil, errors.New("OCI IMDS 包含空 VNIC 条目")
		}
		if rawMAC := strings.TrimSpace(v.MACAddr); rawMAC != "" {
			if mac, err := net.ParseMAC(rawMAC); err != nil || len(mac) == 0 {
				return nil, fmt.Errorf("OCI VNIC macAddr 非法: %q", v.MACAddr)
			}
		}
		if rawPriv := strings.TrimSpace(v.PrivateIP); rawPriv != "" {
			addr, err := netip.ParseAddr(rawPriv)
			if err != nil {
				return nil, fmt.Errorf("OCI VNIC privateIp 非法: %q", v.PrivateIP)
			}
			addr = addr.Unmap()
			if !addr.Is4() || addr.IsUnspecified() {
				return nil, fmt.Errorf("OCI VNIC privateIp 非有效 IPv4: %q", v.PrivateIP)
			}
			parsedPrivIPs[i] = addr
		}
	}

	if len(vnics) == 1 {
		if vnics[0].IsPrimary != nil && !*vnics[0].IsPrimary {
			return nil, errors.New("OCI IMDS 唯一 VNIC 显式标记为非主 VNIC")
		}
		return vnics[0], nil
	}

	if !sourceIP.IsValid() || !sourceIP.Is4() || sourceIP.IsUnspecified() {
		return nil, errors.New("OCI 多 VNIC 场景缺少有效 IMDS 请求源 IPv4")
	}

	matchedIdx := -1
	matchCount := 0
	for i, privIP := range parsedPrivIPs {
		if privIP.IsValid() && privIP == sourceIP {
			matchedIdx = i
			matchCount++
		}
	}
	if matchCount == 0 {
		return nil, fmt.Errorf("OCI 多 VNIC 场景 IMDS 源 IPv4 %s 未匹配任何 VNIC privateIp", sourceIP)
	}
	if matchCount > 1 {
		return nil, fmt.Errorf("OCI 多 VNIC 场景 IMDS 源 IPv4 %s 匹配到 %d 个 VNIC", sourceIP, matchCount)
	}

	primary := vnics[matchedIdx]
	if primary.IsPrimary != nil && !*primary.IsPrimary {
		return nil, errors.New("OCI 多 VNIC 场景匹配源 IPv4 的 VNIC 显式标记为非主 VNIC")
	}
	for i, v := range vnics {
		if i != matchedIdx && v.IsPrimary != nil && *v.IsPrimary {
			return nil, errors.New("OCI 多 VNIC 场景 isPrimary 与 IMDS 请求源 IPv4 冲突")
		}
	}
	return primary, nil
}

func selectUsableAssignedIPv6(vnicMAC net.HardwareAddr, assigned []netip.Addr, ifaces []localInterface, prevSelected netip.Addr) (netip.Addr, bool) {
	if len(assigned) == 0 || len(vnicMAC) == 0 {
		return netip.Addr{}, false
	}

	assignedSet := make(map[netip.Addr]struct{}, len(assigned))
	for _, addr := range assigned {
		assignedSet[addr] = struct{}{}
	}

	var matched []localInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 || iface.NoCarrier {
			continue
		}
		if ShouldIgnoreNetInterface(iface.Name) {
			continue
		}
		if len(iface.HardwareAddr) == 0 || !bytes.Equal(iface.HardwareAddr, vnicMAC) {
			continue
		}
		matched = append(matched, iface)
	}
	if len(matched) == 0 {
		return netip.Addr{}, false
	}

	slices.SortFunc(matched, func(a, b localInterface) int {
		aVLAN := strings.Contains(a.Name, ".")
		bVLAN := strings.Contains(b.Name, ".")
		if aVLAN != bVLAN {
			if !aVLAN {
				return -1
			}
			return 1
		}
		if a.Index != b.Index {
			if a.Index < b.Index {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})

	type ipv6Candidate struct {
		addr       netip.Addr
		deprecated bool
		ifaceOrder int
	}
	var candidates []ipv6Candidate
	for ifaceOrder, iface := range matched {
		for _, item := range iface.IPv6Addrs {
			if item.Scope != linuxIPv6ScopeGlobal {
				continue
			}
			if !isPublicIPv6(item.Addr) {
				continue
			}
			if item.Flags&(linuxIFAFTemporary|linuxIFAFOptimistic|linuxIFAFDADFailed|linuxIFAFTentative) != 0 {
				continue
			}
			if _, ok := assignedSet[item.Addr]; !ok {
				continue
			}
			candidates = append(candidates, ipv6Candidate{
				addr:       item.Addr,
				deprecated: item.Flags&linuxIFAFDeprecated != 0,
				ifaceOrder: ifaceOrder,
			})
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, false
	}

	slices.SortFunc(candidates, func(a, b ipv6Candidate) int {
		if a.deprecated != b.deprecated {
			if !a.deprecated {
				return -1
			}
			return 1
		}
		if a.ifaceOrder != b.ifaceOrder {
			if a.ifaceOrder < b.ifaceOrder {
				return -1
			}
			return 1
		}
		return a.addr.Compare(b.addr)
	})

	hasNonDeprecated := !candidates[0].deprecated
	if prevSelected.IsValid() {
		for _, c := range candidates {
			if c.addr == prevSelected && (!c.deprecated || !hasNonDeprecated) {
				return c.addr, true
			}
		}
	}
	return candidates[0].addr, true
}

func isPublicIPv6(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
		return false
	}
	if addr.As16()[0]&0xe0 != 0x20 {
		return false
	}
	for _, prefix := range nonPublicIPv6Prefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func readLinuxInterfaces(
	hostRoot string,
	listIfaces func() ([]net.Interface, error),
	ifaceAddrs func(net.Interface) ([]net.Addr, error),
	procPath string,
) ([]localInterface, error) {
	ifaces, err := listIfaces()
	if err != nil {
		return nil, err
	}

	var entries []procIfInet6Entry
	procMissing := false
	f, err := os.Open(procPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		procMissing = true
	} else {
		entries, err = parseProcIfInet6(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}

	out := make([]localInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		isCandidate := iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && !ShouldIgnoreNetInterface(iface.Name)
		if procMissing && isCandidate {
			addrs, addrErr := ifaceAddrs(iface)
			if addrErr != nil {
				return nil, addrErr
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil {
					if addr, ok := netip.AddrFromSlice(ip); ok && isPublicIPv6(addr.Unmap()) {
						return nil, errors.New("缺少 /proc/net/if_inet6，无法校验 IPv6 地址标志")
					}
				}
			}
		}

		noCarrier := false
		if isCandidate && iface.Flags&net.FlagRunning != 0 {
			noCarrier = readLinuxEthernetNoCarrier(hostRoot, iface.Name)
		}

		li := localInterface{
			Index:        iface.Index,
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr,
			Flags:        iface.Flags,
			NoCarrier:    noCarrier,
		}
		for _, entry := range entries {
			if matchIfInet6Entry(iface.Index, iface.Name, entry) {
				li.IPv6Addrs = append(li.IPv6Addrs, localIPv6Addr{
					Addr:  entry.Addr,
					Scope: entry.Scope,
					Flags: entry.Flags,
				})
			}
		}
		out = append(out, li)
	}
	return out, nil
}

func readLinuxEthernetNoCarrier(hostRoot, ifaceName string) bool {
	if ifaceName == "" || strings.Contains(ifaceName, "/") || strings.Contains(ifaceName, "..") {
		return false
	}
	for _, sysRoot := range linuxSysRoots(hostRoot) {
		netDir := filepath.Join(sysRoot, "class", "net", ifaceName)
		info, err := os.Stat(netDir)
		if err != nil || !info.IsDir() {
			continue
		}
		typeRaw, err := os.ReadFile(filepath.Join(netDir, "type"))
		if err != nil {
			return false
		}
		// ARPHRD_ETHER == 1
		if strings.TrimSpace(string(typeRaw)) != "1" {
			return false
		}
		carrierRaw, err := os.ReadFile(filepath.Join(netDir, "carrier"))
		if err != nil {
			return false
		}
		return strings.TrimSpace(string(carrierRaw)) == "0"
	}
	return false
}

func matchIfInet6Entry(ifaceIndex int, ifaceName string, entry procIfInet6Entry) bool {
	if entry.IfIndex > 0 && ifaceIndex > 0 {
		return entry.IfIndex == ifaceIndex
	}
	return entry.IfName == ifaceName
}

func parseProcIfInet6(r io.Reader) ([]procIfInet6Entry, error) {
	scanner := bufio.NewScanner(r)
	var entries []procIfInet6Entry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return nil, fmt.Errorf("if_inet6 行格式无效: %q", line)
		}
		if len(fields[0]) != 32 {
			return nil, fmt.Errorf("if_inet6 IPv6 十六进制长度无效: %q", fields[0])
		}
		rawAddr, err := hex.DecodeString(fields[0])
		if err != nil || len(rawAddr) != 16 {
			return nil, fmt.Errorf("if_inet6 IPv6 十六进制解析失败: %q", fields[0])
		}
		var b [16]byte
		copy(b[:], rawAddr)
		addr := netip.AddrFrom16(b)

		ifIndex, err := strconv.ParseInt(fields[1], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("if_inet6 ifindex 解析失败: %q", fields[1])
		}
		if _, err := strconv.ParseUint(fields[2], 16, 8); err != nil {
			return nil, fmt.Errorf("if_inet6 prefix_len 解析失败: %q", fields[2])
		}
		scopeVal, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("if_inet6 scope 解析失败: %q", fields[3])
		}
		flagsVal, err := strconv.ParseUint(fields[4], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("if_inet6 flags 解析失败: %q", fields[4])
		}

		entries = append(entries, procIfInet6Entry{
			Addr:    addr,
			IfIndex: int(ifIndex),
			Scope:   uint8(scopeVal),
			Flags:   uint32(flagsVal),
			IfName:  fields[5],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func linuxSysRoots(hostRoot string) []string {
	roots := make([]string, 0, 3)
	if envSys := strings.TrimSpace(os.Getenv("HOST_SYS")); envSys != "" {
		roots = append(roots, envSys)
	}
	if root := strings.TrimSpace(hostRoot); root != "" && root != "/" {
		roots = append(roots, filepath.Join(root, "sys"))
	}
	roots = append(roots, "/sys")
	return roots
}

func detectLinuxDMI(hostRoot string) dmiPlatform {
	roots := linuxSysRoots(hostRoot)
	readField := func(name string) string {
		for _, sysRoot := range roots {
			data, err := os.ReadFile(filepath.Join(sysRoot, "class/dmi/id", name))
			if err == nil {
				return strings.TrimSpace(string(data))
			}
		}
		return ""
	}

	assetTag := readField("chassis_asset_tag")
	if strings.EqualFold(assetTag, ociDMIChassisAssetTag) {
		return dmiOCI
	}

	combined := strings.ToLower(strings.Join([]string{
		assetTag,
		readField("sys_vendor"),
		readField("product_name"),
		readField("bios_vendor"),
	}, "\n"))
	for _, marker := range nonOCIDMIMarkers {
		if strings.Contains(combined, marker) {
			return dmiNonOCI
		}
	}
	return dmiUnknown
}

func cloneIPv6Observation(obs *IPv6Observation) *IPv6Observation {
	if obs == nil {
		return nil
	}
	cp := *obs
	if obs.Assigned != nil {
		cp.Assigned = make([]string, len(obs.Assigned))
		copy(cp.Assigned, obs.Assigned)
	}
	return &cp
}
