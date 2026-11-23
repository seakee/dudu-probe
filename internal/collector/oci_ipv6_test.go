package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPv6ObservationJSONContract(t *testing.T) {
	obsWithAddr := &IPv6Observation{
		State:      IPv6ObservationStateObserved,
		ObservedAt: 1700000000,
		Address:    "2603:c020:4001:100::10",
		Assigned:   []string{"2603:c020:4001:100::10"},
	}
	raw, err := json.Marshal(obsWithAddr)
	if err != nil {
		t.Fatalf("marshal observed with address: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["state"] != "observed" || m["address"] != "2603:c020:4001:100::10" {
		t.Fatalf("unexpected payload: %s", raw)
	}
	if _, ok := m["assigned"].([]any); !ok {
		t.Fatalf("expected assigned array, got: %s", raw)
	}

	obsLocalPending := &IPv6Observation{
		State:      IPv6ObservationStateObserved,
		ObservedAt: 1700000001,
		Assigned:   []string{"2603:c020:4001:100::10"},
	}
	raw, err = json.Marshal(obsLocalPending)
	if err != nil {
		t.Fatalf("marshal observed without address: %v", err)
	}
	m = nil
	_ = json.Unmarshal(raw, &m)
	if _, hasAddr := m["address"]; hasAddr {
		t.Fatalf("expected address to be omitted when empty, got: %s", raw)
	}
	if _, ok := m["assigned"].([]any); !ok {
		t.Fatalf("expected assigned array, got: %s", raw)
	}

	for _, emptyAssigned := range [][]string{{}, nil} {
		obsEmpty := &IPv6Observation{
			State:      IPv6ObservationStateObserved,
			ObservedAt: 1700000002,
			Assigned:   emptyAssigned,
		}
		raw, err = json.Marshal(obsEmpty)
		if err != nil {
			t.Fatalf("marshal empty observed: %v", err)
		}
		if !strings.Contains(string(raw), `"assigned":[]`) {
			t.Fatalf("expected explicit empty array assigned:[], got: %s", raw)
		}
	}

	obsUnavailable := &IPv6Observation{
		State:      IPv6ObservationStateUnavailable,
		ObservedAt: 1700000003,
		Address:    "2603:c020:4001:100::10",
		Assigned:   []string{"2603:c020:4001:100::10"},
	}
	raw, err = json.Marshal(obsUnavailable)
	if err != nil {
		t.Fatalf("marshal unavailable: %v", err)
	}
	m = nil
	_ = json.Unmarshal(raw, &m)
	if m["state"] != "unavailable" {
		t.Fatalf("unexpected state: %s", raw)
	}
	if _, hasAddr := m["address"]; hasAddr {
		t.Fatalf("unavailable must omit address, got: %s", raw)
	}
	if _, hasAssigned := m["assigned"]; hasAssigned {
		t.Fatalf("unavailable must omit assigned, got: %s", raw)
	}

	legacyReq := &ReportRequest{
		Metrics: &MetricPayload{SampledAt: 1700000004},
	}
	raw, err = json.Marshal(legacyReq)
	if err != nil {
		t.Fatalf("marshal legacy ReportRequest: %v", err)
	}
	if strings.Contains(string(raw), "ipv6_observation") {
		t.Fatalf("expected nil ipv6_observation to be omitted, got: %s", raw)
	}
}

func TestParseProcIfInet6(t *testing.T) {
	fixture := `
2603c020400101000000000000000010 02 80 00 80   enp0s3
2603c020400101000000000000000020 02 40 00 00   enp0s3
2603c020400101000000000000000030 02 40 00 01   enp0s3
2603c020400101000000000000000040 02 40 00 40   enp0s3
2603c020400101000000000000000050 02 40 00 08   enp0s3
2603c020400101000000000000000060 02 40 00 20   enp0s3
fe80000000000000000017fffe012345 02 40 20 80   enp0s3
00000000000000000000000000000001 01 80 10 80       lo

`
	entries, err := parseProcIfInet6(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseProcIfInet6 failed: %v", err)
	}
	if len(entries) != 8 {
		t.Fatalf("expected 8 entries, got %d", len(entries))
	}
	if entries[0].Addr != netip.MustParseAddr("2603:c020:4001:100::10") ||
		entries[0].IfIndex != 2 || entries[0].Scope != 0x00 || entries[0].Flags != 0x80 || entries[0].IfName != "enp0s3" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
	if entries[2].Flags != linuxIFAFTemporary || entries[3].Flags != linuxIFAFTentative || entries[4].Flags != linuxIFAFDADFailed {
		t.Fatalf("unexpected flag entries: %+v", entries[2:5])
	}
	if entries[6].Scope != 0x20 || entries[7].Scope != 0x10 {
		t.Fatalf("unexpected scopes: %+v", entries[6:])
	}

	for _, bad := range []string{
		"short 02 80 00 80 ens3\n",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 02 80 00 80 ens3\n",
		"2603c020400101000000000000000010 02 80 00\n",
		"2603c020400101000000000000000010 02 80 zz 80 ens3\n",
	} {
		if _, err := parseProcIfInet6(strings.NewReader(bad)); err == nil {
			t.Fatalf("expected parse error for %q", bad)
		}
	}
}

func TestOCIIMDSDirectTransportNoProxyNoRedirectsAndAuth(t *testing.T) {
	// 确认默认 IMDS 客户端显式禁用环境代理
	defaultCli := newOCIIMDSClient(ociIMDSTimeout)
	tr, ok := defaultCli.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.Proxy != nil {
		t.Fatal("expected Proxy to be nil so environment proxies are never used")
	}

	// 设置不可达代理环境变量，验证请求仍直连本地测试服务
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")

	var redirectHits atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:01:23:45","ipv6Addresses":["2603:c020:4001:100::1"]}]`))
	}))
	defer redirectTarget.Close()

	var mode atomic.Int32 // 0=ok, 1=redirect, 2=slow
	var sawAuth atomic.Bool
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get(ociIMDSAuthHeader) == ociIMDSAuthValue {
			sawAuth.Store(true)
		}
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
		case 2:
			select {
			case <-r.Context().Done():
			case <-time.After(400 * time.Millisecond):
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:01:23:45","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::1"]}]`))
		}
	}))
	defer imds.Close()

	mac, _ := net.ParseMAC("02:00:17:01:23:45")
	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = imds.URL
	obs.imdsTimeout = 60 * time.Millisecond
	obs.httpClient = newOCIIMDSClient(60 * time.Millisecond)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return time.Unix(1700000000, 0) }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{
			{
				Index:        2,
				Name:         "enp0s3",
				HardwareAddr: mac,
				Flags:        net.FlagUp | net.FlagRunning,
				IPv6Addrs: []localIPv6Addr{
					{Addr: netip.MustParseAddr("2603:c020:4001:100::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				},
			},
		}, nil
	}

	got := obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::1" {
		t.Fatalf("expected observed result bypassing proxy env, got %+v", got)
	}
	if !sawAuth.Load() {
		t.Fatal("expected Authorization: Bearer Oracle header")
	}

	// 验证不跟随 302 重定向
	mode.Store(1)
	got = obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateUnavailable || got.Address != "" || got.Assigned != nil {
		t.Fatalf("expected unavailable on redirect response, got %+v", got)
	}
	if redirectHits.Load() != 0 {
		t.Fatalf("expected redirect target never called, got %d hits", redirectHits.Load())
	}

	// 验证请求超时严格受限于 imdsTimeout
	mode.Store(2)
	start := time.Now()
	got = obs.Observe(context.Background(), true)
	elapsed := time.Since(start)
	if got == nil || got.State != IPv6ObservationStateUnavailable {
		t.Fatalf("expected unavailable on slow IMDS timeout, got %+v", got)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("expected bounded IMDS timeout, took %s", elapsed)
	}
}

func TestOCIIPv6ObservationGenuineEmptyVsIMDSError(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:11:22:33")
	newFixture := func(handler http.HandlerFunc) *ociIPv6Observer {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)

		obs := newOCIIPv6Observer("/")
		obs.goos = "linux"
		obs.imdsURL = srv.URL
		obs.httpClient = newOCIIMDSClient(time.Second)
		obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
		obs.now = func() time.Time { return time.Unix(1700000010, 0) }
		obs.interfacesFn = func() ([]localInterface, error) {
			return []localInterface{
				{
					Index:        2,
					Name:         "eth0",
					HardwareAddr: mac,
					Flags:        net.FlagUp | net.FlagRunning,
				},
			}, nil
		}
		return obs
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "empty array", body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":0,"ipv6Addresses":[]}]`},
		{name: "null field", body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":0,"ipv6Addresses":null}]`},
		{name: "omitted field", body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":0}]`},
		{name: "single vnic nicIndex 1", body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":1}]`},
	} {
		t.Run("genuine_"+tc.name, func(t *testing.T) {
			obs := newFixture(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			got := obs.Observe(context.Background(), true)
			if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "" {
				t.Fatalf("expected observed empty assignment, got %+v", got)
			}
			if got.Assigned == nil || len(got.Assigned) != 0 {
				t.Fatalf("expected non-nil empty Assigned slice, got %#v", got.Assigned)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "http 500", status: http.StatusInternalServerError, body: "boom"},
		{name: "http 404", status: http.StatusNotFound, body: "not found"},
		{name: "invalid json", status: http.StatusOK, body: `[{bad`},
		{name: "empty vnic list", status: http.StatusOK, body: `[]`},
		{name: "missing mac", status: http.StatusOK, body: `[{"nicIndex":0,"ipv6Addresses":[]}]`},
		{name: "explicitly secondary single vnic", status: http.StatusOK, body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":0,"isPrimary":false,"ipv6Addresses":[]}]`},
		{name: "null vnic item", status: http.StatusOK, body: `[null]`},
		{name: "mixed null vnic item", status: http.StatusOK, body: `[{"macAddr":"02:00:17:11:22:33","privateIp":"127.0.0.1","nicIndex":0},null]`},
		{name: "non-array object", status: http.StatusOK, body: `{"macAddr":"02:00:17:11:22:33","nicIndex":0}`},
		{name: "ipv6Addresses non-array", status: http.StatusOK, body: `[{"macAddr":"02:00:17:11:22:33","nicIndex":0,"ipv6Addresses":"2603:c020:4001:100::1"}]`},
	} {
		t.Run("error_"+tc.name, func(t *testing.T) {
			obs := newFixture(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			got := obs.Observe(context.Background(), true)
			if got == nil || got.State != IPv6ObservationStateUnavailable {
				t.Fatalf("expected unavailable, got %+v", got)
			}
			if got.Address != "" || got.Assigned != nil {
				t.Fatalf("unavailable must not carry address or assigned, got %+v", got)
			}
		})
	}
}

func TestOCIIPv6ObservationMACMatchingAndInterfaceFlags(t *testing.T) {
	primaryMAC, _ := net.ParseMAC("02:00:17:aa:bb:cc")
	wrongMAC, _ := net.ParseMAC("02:00:17:00:00:99")

	// 次网卡排在前面、主网卡排在后面，共享 nicIndex:0，通过实际 IMDS 请求源 IPv4 (127.0.0.1) 唯一识别主网卡；MAC 使用大写连字符形式
	imdsBody := `[
		{"macAddr":"02:00:17:00:00:99","privateIp":"10.0.2.2","nicIndex":0,"ipv6Addresses":["2603:c020:4001:200::1"]},
		{"macAddr":"02-00-17-AA-BB-CC","privateIp":"127.0.0.1","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::20"]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(imdsBody))
	}))
	defer srv.Close()

	var currentIfaces []localInterface
	var ifacesErr error

	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return time.Unix(1700000100, 0) }
	obs.interfacesFn = func() ([]localInterface, error) {
		return currentIfaces, ifacesErr
	}

	// 1. 验证跳过临时/乐观/DAD失败/tentative/链路本地/ULA/未分配地址，并选中非 ens3 网卡上有效的 SLAAC/DHCPv6(0x00) 地址
	currentIfaces = []localInterface{
		{
			Index:        1,
			Name:         "docker0",
			HardwareAddr: primaryMAC,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		},
		{
			Index:        2,
			Name:         "eth1",
			HardwareAddr: wrongMAC,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:200::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		},
		{
			Index:        3,
			Name:         "enX0",
			HardwareAddr: primaryMAC,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("fe80::1"), Scope: 0x20, Flags: 0x80},
				{Addr: netip.MustParseAddr("fd00::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::99"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80}, // 不在 assigned 中
				{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: linuxIFAFTemporary},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x00}, // 可用非临时 SLAAC/DHCPv6
			},
		},
	}

	got := obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved {
		t.Fatalf("expected observed, got %+v", got)
	}
	if got.Address != "2603:c020:4001:100::20" {
		t.Fatalf("expected 2603:c020:4001:100::20, got %q", got.Address)
	}

	// 2. 验证 tentative / dadfailed / optimistic / DOWN 网卡均不会选出 address，但保留 observed + assigned
	for _, tc := range []struct {
		name   string
		ifaces []localInterface
	}{
		{
			name: "tentative",
			ifaces: []localInterface{{
				Index: 3, Name: "enX0", HardwareAddr: primaryMAC, Flags: net.FlagUp | net.FlagRunning,
				IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: linuxIFAFTentative}},
			}},
		},
		{
			name: "dadfailed",
			ifaces: []localInterface{{
				Index: 3, Name: "enX0", HardwareAddr: primaryMAC, Flags: net.FlagUp | net.FlagRunning,
				IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: linuxIFAFDADFailed}},
			}},
		},
		{
			name: "optimistic",
			ifaces: []localInterface{{
				Index: 3, Name: "enX0", HardwareAddr: primaryMAC, Flags: net.FlagUp | net.FlagRunning,
				IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: linuxIFAFOptimistic}},
			}},
		},
		{
			name: "interface down",
			ifaces: []localInterface{{
				Index: 3, Name: "enX0", HardwareAddr: primaryMAC, Flags: 0,
				IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80}},
			}},
		},
		{
			name: "no carrier (IFF_UP without IFF_RUNNING)",
			ifaces: []localInterface{{
				Index: 3, Name: "enX0", HardwareAddr: primaryMAC, Flags: net.FlagUp,
				IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80}},
			}},
		},
		{
			name:   "no matching mac interface",
			ifaces: []localInterface{{Index: 2, Name: "eth1", HardwareAddr: wrongMAC, Flags: net.FlagUp | net.FlagRunning}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			currentIfaces = tc.ifaces
			res := obs.Observe(context.Background(), true)
			if res == nil || res.State != IPv6ObservationStateObserved || res.Address != "" {
				t.Fatalf("expected observed with omitted address, got %+v", res)
			}
			if !slices.Equal(res.Assigned, []string{"2603:c020:4001:100::20"}) {
				t.Fatalf("unexpected assigned: %+v", res.Assigned)
			}
		})
	}

	// 3. 本地网卡读取失败 -> unavailable
	ifacesErr = errors.New("netlink failed")
	res := obs.Observe(context.Background(), true)
	if res == nil || res.State != IPv6ObservationStateUnavailable || res.Address != "" || res.Assigned != nil {
		t.Fatalf("expected unavailable on interface error, got %+v", res)
	}
}

func TestOCIIPv6ObservationMultipleAddressesStable(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:55:66:77")
	var imdsJSON atomic.Value
	imdsJSON.Store(`[{"macAddr":"02:00:17:55:66:77","nicIndex":0,"ipv6Addresses":["2603:C020:4001:0100::20","2603:c020:4001:0100:0000:0000:0000:0010","2603:c020:4001:100::10"]}]`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(imdsJSON.Load().(string)))
	}))
	defer srv.Close()

	now := time.Unix(1700000200, 0)
	var addrs []localIPv6Addr

	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return now }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "enp1s0",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs:    addrs,
		}}, nil
	}

	// 1. 首次冷启动：非规范格式去重排序，选择最小地址 ::10
	addrs = []localIPv6Addr{
		{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
		{Addr: netip.MustParseAddr("2603:c020:4001:100::10"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
	}
	got := obs.Observe(context.Background(), false)
	if got == nil || got.Address != "2603:c020:4001:100::10" {
		t.Fatalf("expected ::10, got %+v", got)
	}
	if !slices.Equal(got.Assigned, []string{"2603:c020:4001:100::10", "2603:c020:4001:100::20"}) {
		t.Fatalf("unexpected canonical assigned: %+v", got.Assigned)
	}

	// 2. 新增更小地址 ::5 且打乱顺序，粘性保持原有有效非废弃地址 ::10 不抖动
	now = now.Add(60 * time.Second)
	imdsJSON.Store(`[{"macAddr":"02:00:17:55:66:77","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::20","2603:c020:4001:100::5","2603:c020:4001:100::10"]}]`)
	addrs = []localIPv6Addr{
		{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
		{Addr: netip.MustParseAddr("2603:c020:4001:100::5"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
		{Addr: netip.MustParseAddr("2603:c020:4001:100::10"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
	}
	got = obs.Observe(context.Background(), false)
	if got == nil || got.Address != "2603:c020:4001:100::10" {
		t.Fatalf("expected sticky ::10, got %+v", got)
	}

	// 3. 若 ::10 变为 deprecated 而 ::5 非 deprecated，则平稳切换到 ::5
	now = now.Add(60 * time.Second)
	addrs = []localIPv6Addr{
		{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
		{Addr: netip.MustParseAddr("2603:c020:4001:100::5"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
		{Addr: netip.MustParseAddr("2603:c020:4001:100::10"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80 | linuxIFAFDeprecated},
	}
	got = obs.Observe(context.Background(), false)
	if got == nil || got.Address != "2603:c020:4001:100::5" {
		t.Fatalf("expected switch to non-deprecated ::5, got %+v", got)
	}

	// 4. 若 ::5 被从 IMDS 撤销，则回退选中 ::20
	now = now.Add(60 * time.Second)
	imdsJSON.Store(`[{"macAddr":"02:00:17:55:66:77","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::20","2603:c020:4001:100::10"]}]`)
	got = obs.Observe(context.Background(), false)
	if got == nil || got.Address != "2603:c020:4001:100::20" {
		t.Fatalf("expected failover to ::20, got %+v", got)
	}
}

func TestOCIIPv6ObservationInvalidIPv6(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:88:99:00")
	var imdsJSON atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(imdsJSON.Load().(string)))
	}))
	defer srv.Close()

	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return time.Unix(1700000300, 0) }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "eth0",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("fe80::1"), Scope: 0x20, Flags: 0x80},
				{Addr: netip.MustParseAddr("fd00::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2001:db8::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		}}, nil
	}

	// 语法错误 / IPv4 / CIDR / zone / null 元素 -> fail closed unavailable
	for _, body := range []string{
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["not-an-ip"]}]`,
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::1","bad-ip"]}]`,
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["10.0.0.1"]}]`,
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::1/64"]}]`,
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["fe80::1%eth0"]}]`,
		`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":[null]}]`,
	} {
		imdsJSON.Store(body)
		got := obs.Observe(context.Background(), true)
		if got == nil || got.State != IPv6ObservationStateUnavailable || got.Address != "" || got.Assigned != nil {
			t.Fatalf("expected unavailable for malformed ipv6 %s, got %+v", body, got)
		}
	}

	// 非公网 IPv6（ULA / 链路本地 / 文档段 / 6to4 / 回环）单独出现 -> 过滤后 observed assigned:[]
	imdsJSON.Store(`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["fe80::1","fd00::1","::1","2001:db8::1","2001::1","2002::1","3fff::1"]}]`)
	got := obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "" || len(got.Assigned) != 0 {
		t.Fatalf("expected observed empty assigned when only non-public IPv6 present, got %+v", got)
	}

	// 非公网与合法公网混杂 -> 仅保留合法公网 IPv6
	imdsJSON.Store(`[{"macAddr":"02:00:17:88:99:00","nicIndex":0,"ipv6Addresses":["fd00::1","2001:db8::1","2603:c020:4001:100::1"]}]`)
	got = obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::1" || !slices.Equal(got.Assigned, []string{"2603:c020:4001:100::1"}) {
		t.Fatalf("expected only valid public IPv6 preserved, got %+v", got)
	}
}

func TestOCIIPv6ObservationTransientErrorsAndRecovery(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:22:33:44")
	var failIMDS atomic.Bool
	failIMDS.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failIMDS.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:22:33:44","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::20","2603:c020:4001:100::10"]}]`))
	}))
	defer srv.Close()

	now := time.Unix(1700000400, 0)
	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return now }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "eth0",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::10"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		}}, nil
	}

	// 启动阶段瞬时失败 -> unavailable
	got := obs.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateUnavailable || got.ObservedAt != now.Unix() {
		t.Fatalf("expected startup unavailable on OCI, got %+v", got)
	}

	// +60s 恢复 -> observed
	now = now.Add(60 * time.Second)
	failIMDS.Store(false)
	got = obs.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::10" || got.ObservedAt != now.Unix() {
		t.Fatalf("expected recovery to observed, got %+v", got)
	}

	// +120s 再次瞬时失败 -> unavailable，但随后 +180s 恢复仍保持 ::10 粘性
	now = now.Add(60 * time.Second)
	failIMDS.Store(true)
	got = obs.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateUnavailable || got.ObservedAt != now.Unix() {
		t.Fatalf("expected transient unavailable, got %+v", got)
	}

	now = now.Add(60 * time.Second)
	failIMDS.Store(false)
	got = obs.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::10" {
		t.Fatalf("expected sticky recovery to ::10, got %+v", got)
	}
}

func TestOCIIPv6ObservationNonLinuxNonOCIAndDMI(t *testing.T) {
	// 1. 非 Linux 平台直接跳过（零网络调用）
	for _, goos := range []string{"darwin", "windows"} {
		var imdsHits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			imdsHits.Add(1)
		}))
		obs := newOCIIPv6Observer("/")
		obs.goos = goos
		obs.imdsURL = srv.URL
		if got := obs.Observe(context.Background(), true); got != nil {
			srv.Close()
			t.Fatalf("expected nil on %s, got %+v", goos, got)
		}
		srv.Close()
		if imdsHits.Load() != 0 {
			t.Fatalf("expected 0 IMDS hits on %s, got %d", goos, imdsHits.Load())
		}
	}

	// 2. DMI 文件解析测试（通过 HOST_SYS 注入）
	tmpSys := t.TempDir()
	dmiDir := filepath.Join(tmpSys, "class", "dmi", "id")
	if err := os.MkdirAll(dmiDir, 0o755); err != nil {
		t.Fatalf("mkdir dmi: %v", err)
	}
	t.Setenv("HOST_SYS", tmpSys)

	if err := os.WriteFile(filepath.Join(dmiDir, "chassis_asset_tag"), []byte("OracleCloud.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("QEMU\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectLinuxDMI("/"); got != dmiOCI {
		t.Fatalf("expected dmiOCI, got %v", got)
	}

	_ = os.WriteFile(filepath.Join(dmiDir, "chassis_asset_tag"), []byte("Not Specified\n"), 0o644)
	if got := detectLinuxDMI("/"); got != dmiUnknown {
		t.Fatalf("expected dmiUnknown for generic QEMU, got %v", got)
	}

	// 回退 sysRoot 即使存在非 OCI 标记，也不得与已命中的 HOST_SYS DMI 目录混读字段
	fallbackRoot := t.TempDir()
	fallbackDMI := filepath.Join(fallbackRoot, "sys", "class", "dmi", "id")
	if err := os.MkdirAll(fallbackDMI, 0o755); err != nil {
		t.Fatalf("mkdir fallback dmi: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fallbackDMI, "product_name"), []byte("Virtual Machine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fallbackDMI, "bios_vendor"), []byte("Microsoft Corporation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectLinuxDMI(fallbackRoot); got != dmiUnknown {
		t.Fatalf("expected HOST_SYS dmi dir not to mix fields from fallback root, got %v", got)
	}

	_ = os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("Hetzner\n"), 0o644)
	if got := detectLinuxDMI("/"); got != dmiNonOCI {
		t.Fatalf("expected dmiNonOCI for Hetzner, got %v", got)
	}

	// 3. 明确非 OCI 平台直接跳过（零 IMDS 调用）
	var nonOCIHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonOCIHits.Add(1)
	}))
	defer srv.Close()

	obsNonOCI := newOCIIPv6Observer("/")
	obsNonOCI.goos = "linux"
	obsNonOCI.imdsURL = srv.URL
	obsNonOCI.dmiDetectFn = func() dmiPlatform { return dmiNonOCI }
	if got := obsNonOCI.Observe(context.Background(), false); got != nil {
		t.Fatalf("expected nil on explicit non-OCI, got %+v", got)
	}
	if nonOCIHits.Load() != 0 {
		t.Fatalf("expected 0 IMDS hits on explicit non-OCI, got %d", nonOCIHits.Load())
	}

	// 4. 未知 DMI 且非 OCI（IMDS 返回 404）：返回 nil 不污染节点状态，且 3 次后进入 30m 退避
	var unknownHits atomic.Int32
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unknownHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv404.Close()

	now := time.Unix(1700000500, 0)
	obsUnknown := newOCIIPv6Observer("/")
	obsUnknown.goos = "linux"
	obsUnknown.imdsURL = srv404.URL
	obsUnknown.httpClient = newOCIIMDSClient(time.Second)
	obsUnknown.dmiDetectFn = func() dmiPlatform { return dmiUnknown }
	obsUnknown.now = func() time.Time { return now }

	for range 4 {
		if got := obsUnknown.Observe(context.Background(), false); got != nil {
			t.Fatalf("expected nil for unconfirmed non-OCI, got %+v", got)
		}
		now = now.Add(60 * time.Second)
	}
	if unknownHits.Load() != ociUnconfirmedMaxFast {
		t.Fatalf("expected %d fast attempts before backoff, got %d", ociUnconfirmedMaxFast, unknownHits.Load())
	}

	// 5. 未知 DMI（如未挂载 /sys 的 OCI 容器）在 IMDS 返回 200 后确认 OCI，后续瞬时故障可回报 unavailable
	var failAfterConfirm atomic.Bool
	mac, _ := net.ParseMAC("02:00:17:66:77:88")
	srvContainer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failAfterConfirm.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:66:77:88","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::7"]}]`))
	}))
	defer srvContainer.Close()

	now = time.Unix(1700000600, 0)
	obsContainer := newOCIIPv6Observer("/")
	obsContainer.goos = "linux"
	obsContainer.imdsURL = srvContainer.URL
	obsContainer.httpClient = newOCIIMDSClient(time.Second)
	obsContainer.dmiDetectFn = func() dmiPlatform { return dmiUnknown }
	obsContainer.now = func() time.Time { return now }
	obsContainer.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "eth0",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::7"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		}}, nil
	}

	got := obsContainer.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::7" {
		t.Fatalf("expected container OCI auto-confirm observed, got %+v", got)
	}
	now = now.Add(60 * time.Second)
	failAfterConfirm.Store(true)
	got = obsContainer.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateUnavailable {
		t.Fatalf("expected unavailable after earlier OCI confirmation, got %+v", got)
	}
}

func TestOCIIPv6Observation60sCadenceIndependentOfHostMetaAndPreservesTimestamp(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:aa:11:22")
	var imdsCalls atomic.Int32
	var imdsAddr atomic.Value
	imdsAddr.Store("2603:c020:4001:100::1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imdsCalls.Add(1)
		addr := imdsAddr.Load().(string)
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:aa:11:22","nicIndex":0,"ipv6Addresses":["` + addr + `"]}]`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := New("/")
	now := time.Unix(1700001000, 0)
	col.ipv6Observer.goos = "linux"
	col.ipv6Observer.imdsURL = srv.URL
	col.ipv6Observer.httpClient = newOCIIMDSClient(time.Second)
	col.ipv6Observer.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	col.ipv6Observer.now = func() time.Time { return now }
	col.ipv6Observer.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "ens5",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::2"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		}}, nil
	}

	// 启动采集 HostMeta（5 分钟缓存）
	_ = col.CollectHostMeta(ctx, true)
	col.mu.Lock()
	col.cachedMeta.Hostname = "hostmeta-5m-sentinel"
	col.mu.Unlock()

	// t=0s: 首次采集 IPv6
	obs0 := col.CollectIPv6Observation(ctx, false)
	if obs0 == nil || obs0.ObservedAt != 1700001000 || obs0.Address != "2603:c020:4001:100::1" {
		t.Fatalf("unexpected initial observation: %+v", obs0)
	}
	if imdsCalls.Load() != 1 {
		t.Fatalf("expected 1 IMDS call, got %d", imdsCalls.Load())
	}

	// t=10s & t=59s: 复用缓存，不打 IMDS，且绝不替换 ObservedAt
	for _, step := range []time.Duration{10 * time.Second, 59 * time.Second} {
		now = time.Unix(1700001000, 0).Add(step)
		cached := col.CollectIPv6Observation(ctx, false)
		if cached == nil || cached.ObservedAt != 1700001000 {
			t.Fatalf("at +%s expected preserved ObservedAt=1700001000, got %+v", step, cached)
		}
		if imdsCalls.Load() != 1 {
			t.Fatalf("at +%s expected cached hit without IMDS call, got %d calls", step, imdsCalls.Load())
		}
		// 外部篡改返回切片不应污染内部缓存
		cached.Assigned[0] = "mutated"
	}
	cachedAgain := col.CollectIPv6Observation(ctx, false)
	if !bytes.Equal([]byte(cachedAgain.Assigned[0]), []byte("2603:c020:4001:100::1")) {
		t.Fatalf("expected cloned cache unaffected by caller mutation, got %+v", cachedAgain.Assigned)
	}

	// t=60s: HostMeta 仍命中 5 分钟缓存，但 IPv6 观测独立刷新
	now = time.Unix(1700001060, 0)
	imdsAddr.Store("2603:c020:4001:100::2")
	meta60 := col.CollectHostMeta(ctx, false)
	if meta60.Hostname != "hostmeta-5m-sentinel" {
		t.Fatalf("expected HostMeta 5m cache intact at 60s, got %q", meta60.Hostname)
	}
	obs60 := col.CollectIPv6Observation(ctx, false)
	if obs60 == nil || obs60.ObservedAt != 1700001060 || obs60.Address != "2603:c020:4001:100::2" {
		t.Fatalf("expected 60s IPv6 refresh, got %+v", obs60)
	}
	if imdsCalls.Load() != 2 {
		t.Fatalf("expected 2 IMDS calls at 60s, got %d", imdsCalls.Load())
	}

	// forceRefresh HostMeta 不影响 IPv6 60s 节流周期
	now = time.Unix(1700001070, 0)
	_ = col.CollectHostMeta(ctx, true)
	obs70 := col.CollectIPv6Observation(ctx, false)
	if obs70 == nil || obs70.ObservedAt != 1700001060 || imdsCalls.Load() != 2 {
		t.Fatalf("expected HostMeta forceRefresh not to trigger IPv6 IMDS call, got %+v calls=%d", obs70, imdsCalls.Load())
	}
}

type sourceIPConn struct {
	net.Conn
	localIP net.IP
}

func (c *sourceIPConn) LocalAddr() net.Addr {
	if addr, ok := c.Conn.LocalAddr().(*net.TCPAddr); ok {
		return &net.TCPAddr{IP: c.localIP, Port: addr.Port}
	}
	return &net.TCPAddr{IP: c.localIP, Port: 54321}
}

func newSourceIPHTTPClient(timeout time.Duration, sourceIP string) *http.Client {
	cli := newOCIIMDSClient(timeout)
	tr := cli.Transport.(*http.Transport)
	baseDial := (&net.Dialer{Timeout: timeout}).DialContext
	parsed := net.ParseIP(sourceIP)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &sourceIPConn{Conn: conn, localIP: parsed}, nil
	}
	return cli
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestOCIIPv6ObservationMultiVNICSourceIPMatching(t *testing.T) {
	primaryMAC, _ := net.ParseMAC("02:00:17:10:00:01")
	secondaryMAC, _ := net.ParseMAC("02:00:17:20:00:02")

	var imdsBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(imdsBody.Load().(string)))
	}))
	defer srv.Close()

	newObs := func(httpClient *http.Client) *ociIPv6Observer {
		obs := newOCIIPv6Observer("/")
		obs.goos = "linux"
		obs.imdsURL = srv.URL
		obs.httpClient = httpClient
		obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
		obs.now = func() time.Time { return time.Unix(1700001200, 0) }
		obs.interfacesFn = func() ([]localInterface, error) {
			return []localInterface{
				{
					Index:        2,
					Name:         "ens3",
					HardwareAddr: primaryMAC,
					Flags:        net.FlagUp | net.FlagRunning,
					IPv6Addrs: []localIPv6Addr{
						{Addr: netip.MustParseAddr("2603:c020:4001:100::10"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
					},
				},
				{
					Index:        3,
					Name:         "ens5",
					HardwareAddr: secondaryMAC,
					Flags:        net.FlagUp | net.FlagRunning,
					IPv6Addrs: []localIPv6Addr{
						{Addr: netip.MustParseAddr("2603:c020:4001:200::20"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
					},
				},
			}, nil
		}
		return obs
	}

	// 1. 共享 nicIndex:0 + 乱序 VNIC（次 VNIC 在前，主 VNIC 在后，及相反顺序），通过源 IPv4 (10.0.0.10) 唯一识别主 VNIC
	vnicPrimary := `{"vnicId":"ocid1.vnic.primary","privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::10"]}`
	vnicSecondary := `{"vnicId":"ocid1.vnic.secondary","privateIp":"10.0.1.20","macAddr":"02:00:17:20:00:02","nicIndex":0,"ipv6Addresses":["2603:c020:4001:200::20"]}`
	for _, ordered := range []string{
		"[" + vnicSecondary + "," + vnicPrimary + "]",
		"[" + vnicPrimary + "," + vnicSecondary + "]",
	} {
		imdsBody.Store(ordered)
		obs := newObs(newSourceIPHTTPClient(time.Second, "10.0.0.10"))
		got := obs.Observe(context.Background(), true)
		if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::10" || !slices.Equal(got.Assigned, []string{"2603:c020:4001:100::10"}) {
			t.Fatalf("expected primary VNIC IPv6 via source IP match for %s, got %+v", ordered, got)
		}
	}

	// 2. 主 VNIC 无 IPv6（省略 ipv6Addresses）而次 VNIC 有 IPv6：必须汇报主 VNIC 权威空分配 assigned:[]
	vnicPrimaryNoV6 := `{"vnicId":"ocid1.vnic.primary","privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0}`
	imdsBody.Store("[" + vnicSecondary + "," + vnicPrimaryNoV6 + "]")
	got := newObs(newSourceIPHTTPClient(time.Second, "10.0.0.10")).Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "" || got.Assigned == nil || len(got.Assigned) != 0 {
		t.Fatalf("expected authoritative empty assigned on primary VNIC, got %+v", got)
	}

	// 3. 多 VNIC 无法唯一匹配源 IPv4 时 fail closed (unavailable)，绝不回退到切片首项或 nicIndex:0
	failCases := []struct {
		name       string
		body       string
		httpClient *http.Client
	}{
		{
			name:       "source ip unmatched",
			body:       "[" + vnicPrimary + "," + vnicSecondary + "]",
			httpClient: newSourceIPHTTPClient(time.Second, "10.0.99.99"),
		},
		{
			name:       "duplicate privateIp matches multiple vnics",
			body:       `[{"privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::10"]},{"privateIp":"10.0.0.10","macAddr":"02:00:17:20:00:02","nicIndex":0,"ipv6Addresses":["2603:c020:4001:200::20"]}]`,
			httpClient: newSourceIPHTTPClient(time.Second, "10.0.0.10"),
		},
		{
			name:       "matched vnic explicitly secondary",
			body:       `[{"privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0,"isPrimary":false,"ipv6Addresses":[]},{"privateIp":"10.0.1.20","macAddr":"02:00:17:20:00:02","nicIndex":0}]`,
			httpClient: newSourceIPHTTPClient(time.Second, "10.0.0.10"),
		},
		{
			name:       "contradictory isPrimary on non-matching vnic",
			body:       `[{"privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0},{"privateIp":"10.0.1.20","macAddr":"02:00:17:20:00:02","nicIndex":0,"isPrimary":true}]`,
			httpClient: newSourceIPHTTPClient(time.Second, "10.0.0.10"),
		},
		{
			name:       "malformed privateIp",
			body:       `[{"privateIp":"10.0.0.10","macAddr":"02:00:17:10:00:01","nicIndex":0},{"privateIp":"bad-ip","macAddr":"02:00:17:20:00:02","nicIndex":0}]`,
			httpClient: newSourceIPHTTPClient(time.Second, "10.0.0.10"),
		},
		{
			name: "missing GotConn source ip",
			body: "[" + vnicPrimary + "," + vnicSecondary + "]",
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("[" + vnicPrimary + "," + vnicSecondary + "]")),
						Header:     make(http.Header),
					}, nil
				}),
			},
		},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			imdsBody.Store(tc.body)
			res := newObs(tc.httpClient).Observe(context.Background(), true)
			if res == nil || res.State != IPv6ObservationStateUnavailable || res.Address != "" || res.Assigned != nil {
				t.Fatalf("expected fail-closed unavailable, got %+v", res)
			}
		})
	}
}

func TestOCIIPv6ObservationOfficialSampleWithoutIPv6(t *testing.T) {
	// Oracle 官方文档 /opc/v2/vnics/ 未分配 IPv6 示例（省略 ipv6Addresses，带 vlanTag 与 "null" 字符串）
	officialSample := `[{
		"vnicId": "ocid1.vnic.oc1.phx.exampleuniqueID",
		"privateIp": "10.0.3.6",
		"secondaryPrivateIps": ["10.0.3.8", "172.16.3.18"],
		"secondaryPrivateIpCidrs": ["10.0.3.64/30", "172.16.3.72/29"],
		"subnetCidrBlock": "10.0.3.0/24",
		"subnetCidrBlocks": ["10.0.3.0/24", "172.16.3.0/24"],
		"ipv6SubnetCidrBlock": "null",
		"ipv6SubnetCidrBlocks": ["fd23:0000:0000:0000:0000:0000:0000:0000/64"],
		"vlanTag": 11,
		"macAddr": "00:00:00:00:00:01",
		"virtualRouterIp": "10.0.3.1",
		"ipv6VirtualRouterIp": "fe80::200:17ff:fe15:6693",
		"nicIndex": 0
	}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(officialSample))
	}))
	defer srv.Close()

	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return time.Unix(1700001300, 0) }

	got := obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "" || got.Assigned == nil || len(got.Assigned) != 0 {
		t.Fatalf("expected observed empty assigned on official OCI sample, got %+v", got)
	}
}

func TestOCIIPv6ObservationNoCarrierAndReadLinuxInterfaces(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:ca:fe:01")
	tmpDir := t.TempDir()
	tmpSys := filepath.Join(tmpDir, "sys")
	netDir := filepath.Join(tmpSys, "class", "net", "eth0")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOST_SYS", tmpSys)

	procPath := filepath.Join(tmpDir, "if_inet6")
	listIfaces := func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 2, Name: "eth0", HardwareAddr: mac, Flags: net.FlagUp | net.FlagRunning},
		}, nil
	}

	// 1. 缺少 /proc/net/if_inet6 且 iface.Addrs 返回错误：不得吞掉错误
	_, err := readLinuxInterfaces("/", listIfaces, func(net.Interface) ([]net.Addr, error) {
		return nil, errors.New("netlink addrs failed")
	}, procPath)
	if err == nil || !strings.Contains(err.Error(), "netlink addrs failed") {
		t.Fatalf("expected iface.Addrs error propagated, got %v", err)
	}

	// 2. 缺少 /proc/net/if_inet6 且 iface.Addrs 存在公网 IPv6：fail closed
	_, err = readLinuxInterfaces("/", listIfaces, func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("2603:c020:4001:100::10"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}, procPath)
	if err == nil {
		t.Fatal("expected error when proc if_inet6 missing with public IPv6")
	}

	// 3. 写入合法 /proc/net/if_inet6，分别测试 sysfs Ethernet carrier=0 与 carrier=1
	procContent := "2603c020400101000000000000000010 02 40 00 80   eth0\n"
	if err := os.WriteFile(procPath, []byte(procContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "type"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "carrier"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:ca:fe:01","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::10"]}]`))
	}))
	defer srv.Close()

	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return time.Unix(1700001400, 0) }
	obs.interfacesFn = func() ([]localInterface, error) {
		return readLinuxInterfaces(obs.hostRoot, listIfaces, func(net.Interface) ([]net.Addr, error) {
			return nil, nil
		}, procPath)
	}

	// sysfs carrier=0 应拒绝地址就绪
	got := obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "" || !slices.Equal(got.Assigned, []string{"2603:c020:4001:100::10"}) {
		t.Fatalf("expected Ethernet no-carrier to omit address, got %+v", got)
	}

	// sysfs carrier=1 + FlagRunning 恢复就绪
	if err := os.WriteFile(filepath.Join(netDir, "carrier"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::10" {
		t.Fatalf("expected address ready with carrier=1, got %+v", got)
	}

	// sysfs carrier 文件不存在（不可验证）时，仍依赖 net.FlagRunning 判定就绪
	_ = os.Remove(filepath.Join(netDir, "carrier"))
	got = obs.Observe(context.Background(), true)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::10" {
		t.Fatalf("expected address ready when sysfs carrier unverifiable and FlagRunning set, got %+v", got)
	}
}

func TestOCIIPv6ObservationCallerExpiryVsIMDSTimeout(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:de:ad:01")
	var delayMS atomic.Int64
	var imdsHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		imdsHits.Add(1)
		if d := time.Duration(delayMS.Load()) * time.Millisecond; d > 0 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(d):
			}
		}
		_, _ = w.Write([]byte(`[{"macAddr":"02:00:17:de:ad:01","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::1"]}]`))
	}))
	defer srv.Close()

	now := time.Unix(1700001500, 0)
	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.imdsTimeout = 80 * time.Millisecond
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiUnknown }
	obs.now = func() time.Time { return now }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index: 2, Name: "eth0", HardwareAddr: mac, Flags: net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{{Addr: netip.MustParseAddr("2603:c020:4001:100::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80}},
		}}, nil
	}

	// 1. 已过期的调用方 DeadlineExceeded / Canceled 不应触发 IMDS、不推进缓存也不增加退避计数
	expiredCtx, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for range 5 {
		if got := obs.Observe(expiredCtx, false); got != nil {
			t.Fatalf("expected nil on pre-expired context, got %+v", got)
		}
	}
	if imdsHits.Load() != 0 {
		t.Fatalf("expected 0 IMDS hits on pre-expired context, got %d", imdsHits.Load())
	}

	// 2. 请求中途调用方上下文先过期（25ms < 80ms imdsTimeout）：不计入退避失败、不推进 nextSampleAt
	delayMS.Store(300)
	for range 4 {
		shortCtx, cancelShort := context.WithTimeout(context.Background(), 25*time.Millisecond)
		got := obs.Observe(shortCtx, false)
		cancelShort()
		if got != nil {
			t.Fatalf("expected nil on caller expiry, got %+v", got)
		}
	}
	obs.mu.Lock()
	failuresAfterCallerExpiry := obs.unconfirmedFailures
	hasSampledAfterCallerExpiry := obs.hasSampled
	obs.mu.Unlock()
	if failuresAfterCallerExpiry != 0 || hasSampledAfterCallerExpiry {
		t.Fatalf("caller expiry must not advance failure backoff or cache state: failures=%d hasSampled=%v",
			failuresAfterCallerExpiry, hasSampledAfterCallerExpiry)
	}

	// 3. 随后调用方上下文健康且 IMDS 恢复：立即正常采样（未进 30m 退避）
	delayMS.Store(0)
	got := obs.Observe(context.Background(), false)
	if got == nil || got.State != IPv6ObservationStateObserved || got.Address != "2603:c020:4001:100::1" {
		t.Fatalf("expected immediate healthy observation after caller expiry, got %+v", got)
	}

	// 4. 在已有有效缓存时遇到调用方 DeadlineExceeded：保留旧缓存且不推迟下一次正常刷新
	now = now.Add(60 * time.Second)
	delayMS.Store(300)
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 25*time.Millisecond)
	cachedOnExpiry := obs.Observe(shortCtx, false)
	cancelShort()
	if cachedOnExpiry == nil || cachedOnExpiry.ObservedAt != 1700001500 {
		t.Fatalf("expected prior cached observation preserved on caller expiry, got %+v", cachedOnExpiry)
	}

	delayMS.Store(0)
	refreshed := obs.Observe(context.Background(), false)
	if refreshed == nil || refreshed.ObservedAt != now.Unix() {
		t.Fatalf("expected immediate refresh on next healthy call after caller expiry, got %+v", refreshed)
	}

	// 5. 内部 IMDS 超时（调用方 ctx 充足，80ms imdsTimeout 到期）应真实记录 unavailable/退避
	obsInternal := newOCIIPv6Observer("/")
	obsInternal.goos = "linux"
	obsInternal.imdsURL = srv.URL
	obsInternal.imdsTimeout = 50 * time.Millisecond
	obsInternal.httpClient = newOCIIMDSClient(time.Second)
	obsInternal.dmiDetectFn = func() dmiPlatform { return dmiUnknown }
	tNow := time.Unix(1700001600, 0)
	obsInternal.now = func() time.Time { return tNow }
	delayMS.Store(300)

	for i := range ociUnconfirmedMaxFast {
		res := obsInternal.Observe(context.Background(), false)
		if res != nil {
			t.Fatalf("attempt %d expected nil on unknown DMI timeout, got %+v", i, res)
		}
		tNow = tNow.Add(60 * time.Second)
	}
	hitsBeforeBackoff := imdsHits.Load()
	_ = obsInternal.Observe(context.Background(), false)
	if imdsHits.Load() != hitsBeforeBackoff {
		t.Fatalf("expected 30m backoff after %d internal IMDS timeouts", ociUnconfirmedMaxFast)
	}
}

func TestOCIIPv6Observation60sPhaseDriftAndBackoff(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:17:33:44:55")
	var imdsCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := imdsCalls.Add(1)
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"macAddr":"02:00:17:33:44:55","nicIndex":0,"ipv6Addresses":["2603:c020:4001:100::%s"]}]`, strconv.Itoa(int(n)))))
	}))
	defer srv.Close()

	base := time.Unix(1700002000, 0)
	now := base
	obs := newOCIIPv6Observer("/")
	obs.goos = "linux"
	obs.imdsURL = srv.URL
	obs.httpClient = newOCIIMDSClient(time.Second)
	obs.dmiDetectFn = func() dmiPlatform { return dmiOCI }
	obs.now = func() time.Time { return now }
	obs.interfacesFn = func() ([]localInterface, error) {
		return []localInterface{{
			Index:        2,
			Name:         "eth0",
			HardwareAddr: mac,
			Flags:        net.FlagUp | net.FlagRunning,
			IPv6Addrs: []localIPv6Addr{
				{Addr: netip.MustParseAddr("2603:c020:4001:100::1"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::2"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::3"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::4"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
				{Addr: netip.MustParseAddr("2603:c020:4001:100::5"), Scope: linuxIPv6ScopeGlobal, Flags: 0x80},
			},
		}}, nil
	}

	// t=0s: 第 1 次采样
	if got := obs.Observe(context.Background(), false); got == nil || got.Address != "2603:c020:4001:100::1" {
		t.Fatalf("unexpected t=0 obs: %+v", got)
	}
	// t=62.5s (抖动晚到 2.5s): 第 2 次采样，相位不漂移
	now = base.Add(62*time.Second + 500*time.Millisecond)
	if got := obs.Observe(context.Background(), false); got == nil || got.Address != "2603:c020:4001:100::2" {
		t.Fatalf("unexpected t=62.5s obs: %+v", got)
	}
	// t=120s (距上次采样仅 57.5s，但已到第 2 个 60s 相位槽): 仍正常刷新，不跳到 180s
	now = base.Add(120 * time.Second)
	if got := obs.Observe(context.Background(), false); got == nil || got.Address != "2603:c020:4001:100::3" {
		t.Fatalf("expected t=120s sample without phase drift, got %+v", got)
	}
	// t=181s -> t=240s
	now = base.Add(181 * time.Second)
	if got := obs.Observe(context.Background(), false); got == nil || got.Address != "2603:c020:4001:100::4" {
		t.Fatalf("unexpected t=181s obs: %+v", got)
	}
	now = base.Add(240 * time.Second)
	if got := obs.Observe(context.Background(), false); got == nil || got.Address != "2603:c020:4001:100::5" {
		t.Fatalf("expected t=240s sample without phase drift, got %+v", got)
	}
	if imdsCalls.Load() != 5 {
		t.Fatalf("expected 5 IMDS calls across 5 60s slots despite jitter, got %d", imdsCalls.Load())
	}
}
