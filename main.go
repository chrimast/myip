package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func canonicalIPKey(ip string) string {
	ip = strings.TrimSpace(ip)
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		return v4.String()
	}
	return p.String()
}

const (
	ListenAddr     = ":8080"
	RequestTimeout = 45 * time.Second
	PerCallTimeout = 8 * time.Second

	// Per-call timeout for RIPEstat/RDAP registry lookups
	RegLookupPerCallTimeout = 2000 * time.Millisecond
	// Per-call timeout for domain补齐 (ipinfo/ipdata/ipwho)
	DomainPerCallTimeout = 1000 * time.Millisecond

	DevFallbackToServerPublicIP = true

	CacheTTL        = 120 * time.Second
	RateLimitPerMin = 60
)

// ---------------------------
// Provider priority configuration
// ---------------------------
//
// This project uses a single-pass enrichment pipeline (no staged T1/T2).
// Provider ordering and field overwrite rules are configured here.
//
// IMPORTANT: The only remaining "Tier-1" concept in this repo is BGP Tier-1 ASNs.
// Do not add enrichment-stage tier concepts back in.

// Provider names (stable keys for priority config & debug)
const (
	ProviderRegistry = "registry"
	ProviderIPAPIIs  = "ipapi.is"
	ProviderIPWho    = "ipwho.is"
	ProviderIPAPICom = "ip-api.com"
	ProviderIPAPIOrg = "ip-api.org"
	ProviderIPInfo   = "ipinfo.io"
	ProviderIPData   = "ipdata.co"
)

// Priority groups (field families)
const (
	prioGeo       = "geo"
	prioASN       = "asn"
	prioOrg       = "org"
	prioISP       = "isp"
	prioAsnDomain = "asn_domain"
	prioOrgDomain = "org_domain"
	prioRegistry  = "registry"
)

// ProviderPriorityOrder defines provider preference per field family.
// Earlier providers win over later ones when both provide non-empty values.
var ProviderPriorityOrder = map[string][]string{
	prioGeo:       {ProviderIPAPIIs, ProviderIPWho, ProviderIPAPICom, ProviderIPAPIOrg, ProviderIPInfo, ProviderIPData},
	prioASN:       {ProviderIPAPIIs, ProviderIPInfo, ProviderIPData, ProviderIPWho, ProviderIPAPICom, ProviderIPAPIOrg},
	prioOrg:       {ProviderIPAPIIs, ProviderIPInfo, ProviderIPData, ProviderIPWho, ProviderIPAPICom, ProviderIPAPIOrg},
	prioISP:       {ProviderIPAPIIs, ProviderIPWho, ProviderIPInfo, ProviderIPData, ProviderIPAPICom, ProviderIPAPIOrg},
	prioAsnDomain: {ProviderIPAPIIs, ProviderIPInfo, ProviderIPData},
	prioOrgDomain: {ProviderIPAPIIs, ProviderIPWho},
	prioRegistry:  {ProviderRegistry, ProviderIPAPIIs},
}

func makeRankMap(order []string) map[string]int {
	m := make(map[string]int, len(order)+1)
	for i, n := range order {
		m[n] = i
	}
	// unknown providers go to the end
	m["*"] = len(order) + 100
	return m
}

// ProviderStep describes one provider invocation in the enrichment pipeline.
// The pipeline is table-driven; steps are configured in the top-level config below.
type ProviderStep struct {
	name    string
	timeout time.Duration
	client  *http.Client
	// fill populates the provided *IPInfo patch (patch.IP is already set).
	fill func(context.Context, *http.Client, *IPInfo) error
	// fetch returns a patch. If set, fill must be nil.
	fetch func(context.Context, *http.Client, string) (IPInfo, error)
	// when decides whether to run the step given current merged data.
	when func(IPInfo) bool
}

type stepClientSel int

const (
	stepClientFull stepClientSel = iota
	stepClientIPAPI
)

type providerStepConfig struct {
	name      string
	timeout   time.Duration
	clientSel stepClientSel
	fill      func(context.Context, *http.Client, *IPInfo) error
	fetch     func(context.Context, *http.Client, string) (IPInfo, error)
	when      func(IPInfo) bool
}

// ---- "when" predicates (no closures) ----

func whenAlways(_ IPInfo) bool { return true }

func whenNeedsRegistry(d IPInfo) bool {
	return strings.TrimSpace(d.Registry) == "" || strings.TrimSpace(d.RegRegion) == ""
}

func whenNeedsBasicFallback(d IPInfo) bool { return needsBasicFallback(d) }

func whenNeedsBasicOrAsnDomain(d IPInfo) bool {
	return needsBasicFallback(d) || strings.TrimSpace(d.AsnDomain) == ""
}

func whenNeedsOrgDomain(d IPInfo) bool { return strings.TrimSpace(d.OrgDomain) == "" }

// fetchRegistryPatch performs the registry/reg_region lookup.
// It is treated as "first paint required" (core completeness).
func fetchRegistryPatch(ctx context.Context, c *http.Client, ip string) (IPInfo, error) {
	rir, cc, err := registryBestEffort(ctx, c, ip)
	if err != nil {
		return IPInfo{}, err
	}
	return IPInfo{IP: ip, Registry: rir, RegRegion: cc}, nil
}

// defaultProviderStepConfigs is a pure, top-level configuration list.
// Reorder/add/remove providers here; runtime clients are injected by BuildProviderSteps().
var defaultProviderStepConfigs = []providerStepConfig{
	// Primary
	{name: ProviderIPAPIIs, timeout: PerCallTimeout, clientSel: stepClientIPAPI, fill: fillFromIPApiIs, when: whenAlways},

	// Registry (required for first paint)
	{name: ProviderRegistry, timeout: RegLookupPerCallTimeout, clientSel: stepClientFull, fetch: fetchRegistryPatch, when: whenNeedsRegistry},

	// Basic fallback providers (only if core geo/asn/org/isp missing)
	{name: ProviderIPWho, timeout: PerCallTimeout, clientSel: stepClientFull, fill: fillFromIPWho, when: whenNeedsBasicFallback},
	{name: ProviderIPAPICom, timeout: PerCallTimeout, clientSel: stepClientFull, fill: fillFromIPAPICom, when: whenNeedsBasicFallback},
	{name: ProviderIPAPIOrg, timeout: PerCallTimeout, clientSel: stepClientFull, fill: fillFromIPApiOrg, when: whenNeedsBasicFallback},

	// ipinfo/ipdata also serve as asn_domain fallbacks; keep current logic by gating on missing field
	{name: ProviderIPInfo, timeout: PerCallTimeout, clientSel: stepClientFull, fill: fillFromIPInfoIO, when: whenNeedsBasicOrAsnDomain},
	{name: ProviderIPData, timeout: PerCallTimeout, clientSel: stepClientFull, fill: fillFromIPDataCo, when: whenNeedsBasicOrAsnDomain},

	// org_domain fallback (keep current logic)
	{name: ProviderIPWho, timeout: DomainPerCallTimeout, clientSel: stepClientFull, fill: fillFromIPWho, when: whenNeedsOrgDomain},
}

// BuildProviderSteps builds the provider pipeline from the top-level pure config.
// This avoids closures in the config and keeps the pipeline easy to adjust.
func BuildProviderSteps(httpc *http.Client, ipapiClient *http.Client) []ProviderStep {
	steps := make([]ProviderStep, 0, len(defaultProviderStepConfigs))
	for _, cfg := range defaultProviderStepConfigs {
		c := httpc
		if cfg.clientSel == stepClientIPAPI {
			c = ipapiClient
		}
		steps = append(steps, ProviderStep{
			name:    cfg.name,
			timeout: cfg.timeout,
			client:  c,
			fill:    cfg.fill,
			fetch:   cfg.fetch,
			when:    cfg.when,
		})
	}
	return steps
}

// ---------------------------
// Global HTTP clients (keep-alive, connection reuse)
// ---------------------------

var transportKeepAlive = &http.Transport{
	Proxy: nil, // disable env/system proxy for DoH
	// (avoids local proxy/MITM causing inconsistent DNS answers)

	DialContext: (&net.Dialer{
		Timeout:   4 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          256,
	MaxIdleConnsPerHost:   32,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 7 * time.Second,
}

// Dedicated transport for ipapi.is: avoid HTTP/2 and reduce reuse-related resets.
var transportIPAPIIs = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   4 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     false,
	MaxIdleConns:          64,
	MaxIdleConnsPerHost:   8,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   6 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 7 * time.Second,
}

var httpClientFast = &http.Client{
	Timeout:   4 * time.Second,
	Transport: transportKeepAlive,
}

var httpClientFull = &http.Client{
	Timeout:   PerCallTimeout,
	Transport: transportKeepAlive,
}

var httpClientIPAPIIs = &http.Client{
	Timeout:   PerCallTimeout,
	Transport: transportIPAPIIs,
}

// ---------------------------
// BGP-only HTTP clients (RIPEstat can be slow for very large ASNs)
// IMPORTANT: We intentionally avoid context.WithTimeout for RIPEstat BGP calls.
// We rely on http.Client.Timeout so that other parts of the pipeline keep their tight budgets.
// ---------------------------

var httpClientBGPFast = &http.Client{
	Timeout:   7 * time.Second,
	Transport: transportKeepAlive,
}

var httpClientBGPFull = &http.Client{
	Timeout:   22 * time.Second,
	Transport: transportKeepAlive,
}

// ---------------------------
// BGP fallback policy helpers
// ---------------------------

// bgpErrIsSoft indicates we should NOT immediately replace realtime with history.
// Soft errors are typically transient: timeouts, rate limits, temporary server errors.
func bgpErrIsSoft(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	sl := strings.ToLower(err.Error())
	if strings.Contains(sl, "timeout") || strings.Contains(sl, "deadline exceeded") {
		return true
	}
	if strings.Contains(sl, "http 429") || strings.Contains(sl, "http 502") || strings.Contains(sl, "http 503") || strings.Contains(sl, "http 504") {
		return true
	}
	return false
}

// bgpRealtimeErrToDebug converts a realtime fetch failure into a compact debug tuple.
// Stage is one of: http/timeout/decode/empty/unknown.
func bgpRealtimeErrToDebug(err error, empty bool) (stage string, msg string, retryable bool) {
	if empty {
		return "empty", "realtime neighbours empty", true
	}
	if err == nil {
		return "unknown", "unknown error", false
	}
	// Timeout
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", err.Error(), true
	}
	sl := strings.ToLower(err.Error())
	if strings.Contains(sl, "timeout") || strings.Contains(sl, "deadline exceeded") {
		return "timeout", err.Error(), true
	}
	// HTTP-ish errors often contain status code text from our fetchers.
	if strings.Contains(sl, "http 429") || strings.Contains(sl, "http 502") || strings.Contains(sl, "http 503") || strings.Contains(sl, "http 504") {
		return "http", err.Error(), true
	}
	if strings.Contains(sl, "unexpected json") || strings.Contains(sl, "decode") || strings.Contains(sl, "unmarshal") {
		return "decode", err.Error(), false
	}
	return "unknown", err.Error(), bgpErrIsSoft(err)
}

// ---------------------------
// API keys
// ---------------------------
// API keys / tokens
// ---------------------------
// 建议：生产环境只用环境变量，不要把 Key/Token 写进代码。
// 本项目支持以下环境变量：
//   - IPAPI_IS_KEY    (ipapi.is)
//   - IPAPI_ORG_KEY   (ipapi.org)
//   - IPINFO_TOKEN    (ipinfo.io)
//   - IPDATA_KEY      (ipdata.co)
//
// Windows PowerShell 示例：
//
//	$env:IPAPI_IS_KEY="..." ; $env:IPAPI_ORG_KEY="..." ; $env:IPINFO_TOKEN="..." ; $env:IPDATA_KEY="..."
//
// Linux/macOS 示例：
//
//	export IPAPI_IS_KEY="..." ; export IPAPI_ORG_KEY="..." ; export IPINFO_TOKEN="..." ; export IPDATA_KEY="..."
//
// 若环境变量为空，将使用下面的默认值（方便你本地直接跑起来；部署时建议清空默认值）。
const (
	defaultIPAPIIsKey  = "1d626744e47c31e88d5f"                                     // ipapi.is
	defaultIPAPIOrgKey = "91db4e60c3cc7daaaf52eb51ed09f41688d3a117"                 // ipapi.org
	defaultIPInfoToken = "2367f0cff78630"                                           // ipinfo.io
	defaultIPDataKey   = "14408a7319c98b044652812d7b187403fcea59b91364ce9c19cbf1d9" // ipdata.co
)

var (
	domainRe = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

	// Domain补齐统计（不记录具体域名，仅统计是否补齐成功）
	asnDomainFillHit  uint64
	asnDomainFillMiss uint64
	orgDomainFillHit  uint64
	orgDomainFillMiss uint64
)

// ---------------------------
// Field source tracking (for /api/health)
// Tracks which upstream provider + field path filled certain key fields.
// ---------------------------

type fieldSourceTracker struct {
	mu sync.Mutex
	// counts[field][source] = n
	counts map[string]map[string]uint64
	// last[field] = source
	last       map[string]string
	lastTarget string
	// last request (per /api/ip call) sources, best-effort
	lastReqTarget  string
	lastReqAtUnix  int64
	lastReqSources map[string]string
}

var fsTrack = &fieldSourceTracker{
	counts:         map[string]map[string]uint64{},
	last:           map[string]string{},
	lastReqSources: map[string]string{},
}

func recordFieldSource(field, source, target string) {
	if field == "" || source == "" {
		return
	}
	fsTrack.mu.Lock()
	defer fsTrack.mu.Unlock()
	m := fsTrack.counts[field]
	if m == nil {
		m = map[string]uint64{}
		fsTrack.counts[field] = m
	}
	m[source]++
	fsTrack.last[field] = source
	if target != "" {
		fsTrack.lastTarget = target
	}
}

func snapshotFieldSources() (counts map[string]map[string]uint64, last map[string]string, lastTarget string, lastReqTarget string, lastReqAtUnix int64, lastReqSources map[string]string) {
	fsTrack.mu.Lock()
	defer fsTrack.mu.Unlock()
	counts = map[string]map[string]uint64{}
	for f, sm := range fsTrack.counts {
		cp := map[string]uint64{}
		for s, n := range sm {
			cp[s] = n
		}
		counts[f] = cp
	}
	last = map[string]string{}
	for f, s := range fsTrack.last {
		last[f] = s
	}
	lastTarget = fsTrack.lastTarget
	return
}

// ---------------------------
// API response envelope
// ---------------------------

type APIResp struct {
	Ok     bool     `json:"ok"`
	Data   IPInfo   `json:"data"`
	Errors []string `json:"errors,omitempty"`
}

// ---------------------------
// HTTP helpers
// ---------------------------

// getJSON performs a GET request and decodes JSON into out.
// It returns a descriptive error on non-2xx responses.
func getJSON(ctx context.Context, c *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	// Some providers behave better with an explicit UA.
	req.Header.Set("User-Agent", "myip/1.0 (+local)")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Best effort: read a small portion to include in error.
		var b [256]byte
		n, _ := resp.Body.Read(b[:])
		msg := strings.TrimSpace(string(b[:n]))
		if msg != "" {
			return fmt.Errorf("http %d: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	// dec.DisallowUnknownFields()
	// 兼容外部 API 字段变动：如果严格失败，再用宽松解析。
	if err := dec.Decode(out); err != nil {
		// retry with relaxed decoder
		if _, ok := out.(*map[string]any); ok {
			return err
		}
		// Re-fetch is expensive; instead do a relaxed decode by re-requesting once.
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err2 != nil {
			return err
		}
		req2.Header.Set("User-Agent", "myip/1.0 (+local)")
		resp2, err2 := c.Do(req2)
		if err2 != nil {
			return err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
			return fmt.Errorf("http %d", resp2.StatusCode)
		}
		dec2 := json.NewDecoder(resp2.Body)
		return dec2.Decode(out)
	}
	return nil
}

// ---------------------------
// Models
// ---------------------------

type ASNNode struct {
	ASN         int    `json:"asn"`
	Name        string `json:"name,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	IsTier1     bool   `json:"is_tier1,omitempty"`
}

type BGPTopology struct {
	ASN           int               `json:"asn"`
	Name          string            `json:"name,omitempty"`
	ExternalLinks map[string]string `json:"external_links,omitempty"`
	Prefix        string            `json:"prefix,omitempty"`
	Source        string            `json:"-"` // internal
	Upstreams     []ASNNode         `json:"upstreams,omitempty"`
}

type IPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	ASNOwner    string `json:"asn_owner"`
	Org         string `json:"org"`
	// AsnDomain: ASN 所有者域名（用于“ASN 所有者”处的链接）
	AsnDomain string `json:"asn_domain"`
	// OrgDomain: 企业/组织域名（用于“企业信息”处的链接）
	OrgDomain string `json:"org_domain"`

	// --- internal source markers (not exposed) ---
	ASNOwnerSource  string `json:"-"`
	AsnDomainSource string `json:"-"`
	OrgSource       string `json:"-"`
	OrgDomainSource string `json:"-"`
	Registry        string `json:"registry"`
	RegRegion       string `json:"reg_region"`
	IPType          string `json:"ip_type"`

	IPSource         string         `json:"ip_source"`
	IPSourceReason   string         `json:"ip_source_reason,omitempty"`
	IPProperty       string         `json:"ip_property"`
	IPPropertyReason string         `json:"ip_property_reason,omitempty"`
	IPPropertyScores map[string]int `json:"ip_property_scores,omitempty"`

	RiskScore     int            `json:"risk_score"`
	RiskReason    string         `json:"risk_reason,omitempty"`
	RiskBreakdown map[string]int `json:"risk_breakdown,omitempty"`
	HumanPercent  float64        `json:"human_percent"`
	BotPercent    float64        `json:"bot_percent"`

	HumanBotReason     string         `json:"humanbot_reason,omitempty"`
	HumanBotBreakdown  map[string]int `json:"humanbot_breakdown,omitempty"`
	RiskConfidence     int            `json:"risk_confidence,omitempty"`
	HumanBotConfidence int            `json:"humanbot_confidence,omitempty"`

	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`

	// --- internal signals (not exposed) ---
	// Note: we reuse these flags across multiple providers
	// (ipapi.is / ipwho.is / ip-api.com / ipapi.org) using a
	// "prefer-true + weight" strategy. They are consumed by
	// IP属性/风险分/人机比.
	IPAPIHosting  *bool  `json:"-"`
	IPAPIProxy    *bool  `json:"-"`
	IPAPIMobile   *bool  `json:"-"`
	IPAPIVPN      *bool  `json:"-"`
	IPAPITOR      *bool  `json:"-"`
	ProxySource   string `json:"-"`
	HostingSource string `json:"-"`
	MobileSource  string `json:"-"`
	VPNSource     string `json:"-"`
	TORSource     string `json:"-"`
	// ipdata.co risk hints (internal only; used for risk score)
	IPAPIThreat         *bool  `json:"-"`
	IPAPIKnownAttacker  *bool  `json:"-"`
	IPAPIKnownAbuser    *bool  `json:"-"`
	ThreatSource        string `json:"-"`
	KnownAttackerSource string `json:"-"`
	KnownAbuserSource   string `json:"-"`

	IPAPIIsCompanyType string `json:"-"`
	IPAPIIsASNType     string `json:"-"`

	// multi-source evidence for weighted merge (internal)
	signalTrueWeight  map[string]int                 `json:"-"`
	signalTrueSources map[string]map[string]struct{} `json:"-"`
}

// ---------------------------
// Cache + Rate Limit
// ---------------------------

type cacheEntry struct {
	val       APIResp
	expiresAt time.Time
}

type cacheStore struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

// ---------------------------
// BGP cache (separate, because BGP is now lazy-loaded)
// ---------------------------

type bgpTopoCacheEntry struct {
	val          *BGPTopology
	freshUntil   time.Time
	staleUntil   time.Time
	refreshing   bool
	refreshingAt time.Time
	lastErr      string
	lastErrAt    time.Time
}

var bgpTopoCache = struct {
	mu sync.Mutex
	m  map[int]*bgpTopoCacheEntry
}{m: map[int]*bgpTopoCacheEntry{}}

// ---------------------------
// BGP cache helpers
// ---------------------------

// bgpTopoGet returns (value, state):
//
//	state == 2 -> fresh
//	state == 1 -> stale (serveable but should revalidate)
//	state == 0 -> missing/expired
func bgpTopoGet(asn int) (*BGPTopology, int) {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	e := bgpTopoCache.m[asn]
	if e == nil || e.val == nil {
		return nil, 0
	}
	now := time.Now()
	if now.Before(e.freshUntil) {
		return e.val, 2
	}
	if now.Before(e.staleUntil) {
		return e.val, 1
	}
	delete(bgpTopoCache.m, asn)
	return nil, 0
}

func bgpTopoGetMeta(asn int) (v *BGPTopology, state int, lastErr string, refreshing bool) {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	e := bgpTopoCache.m[asn]
	if e == nil {
		return nil, 0, "", false
	}
	now := time.Now()
	if now.Before(e.freshUntil) {
		return e.val, 2, e.lastErr, e.refreshing
	}
	if now.Before(e.staleUntil) {
		return e.val, 1, e.lastErr, e.refreshing
	}
	delete(bgpTopoCache.m, asn)
	return nil, 0, "", false
}

func bgpTopoSet(asn int, v *BGPTopology, freshTTL, staleTTL time.Duration) {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	now := time.Now()
	e := bgpTopoCache.m[asn]
	if e == nil {
		e = &bgpTopoCacheEntry{}
		bgpTopoCache.m[asn] = e
	}
	e.val = v
	e.freshUntil = now.Add(freshTTL)
	e.staleUntil = now.Add(staleTTL)
	e.refreshing = false
	e.lastErr = ""
	e.lastErrAt = time.Time{}
}

// bgpTopoTryMarkRefreshing marks an ASN as "refreshing".
// NOTE: Unlike older versions, this will CREATE a placeholder entry on cache-miss.
// This is critical so that a true cache-miss can still trigger background refresh.
func bgpTopoTryMarkRefreshing(asn int) bool {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	e := bgpTopoCache.m[asn]
	if e == nil {
		e = &bgpTopoCacheEntry{
			val:        nil,
			freshUntil: time.Now(),                       // treated as expired
			staleUntil: time.Now().Add(30 * time.Minute), // keep placeholder for a while
			refreshing: false,
		}
		bgpTopoCache.m[asn] = e
	}
	if e.refreshing {
		return false
	}
	e.refreshing = true
	e.refreshingAt = time.Now()
	return true
}

func bgpTopoUnmarkRefreshing(asn int) {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	if e := bgpTopoCache.m[asn]; e != nil {
		e.refreshing = false
		e.refreshingAt = time.Time{}
	}
}

func bgpTopoIsRefreshing(asn int) bool {
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	if e := bgpTopoCache.m[asn]; e != nil {
		if e.refreshing {
			// Safety: if a refresh goroutine got stuck or took too long, release the lock and let callers retry.
			// This prevents the frontend from polling "loading" forever.
			maxAge := 45 * time.Second
			if !e.refreshingAt.IsZero() && time.Since(e.refreshingAt) > maxAge {
				e.refreshing = false
				e.refreshingAt = time.Time{}
				e.lastErr = "ripestat(asn-neighbours): refresh timeout"
				e.lastErrAt = time.Now()
				return false
			}
			return true
		}
		return false
	}
	return false
}

func bgpTopoSetErr(asn int, errStr string) {
	if strings.TrimSpace(errStr) == "" {
		return
	}
	bgpTopoCache.mu.Lock()
	defer bgpTopoCache.mu.Unlock()
	e := bgpTopoCache.m[asn]
	if e == nil {
		e = &bgpTopoCacheEntry{
			val:        nil,
			freshUntil: time.Now(),
			staleUntil: time.Now().Add(30 * time.Minute),
		}
		bgpTopoCache.m[asn] = e
	}
	e.lastErr = errStr
	e.lastErrAt = time.Now()
	// keep refreshing flag as-is; caller controls it
}

type asNameCacheEntry struct {
	name      string
	expiresAt time.Time
	negUntil  time.Time
}

var asNameCache = struct {
	mu sync.Mutex
	m  map[int]*asNameCacheEntry
}{m: map[int]*asNameCacheEntry{}}

func asNameCacheGet(asn int) (name string, ok bool, negative bool) {
	asNameCache.mu.Lock()
	defer asNameCache.mu.Unlock()
	e := asNameCache.m[asn]
	if e == nil {
		return "", false, false
	}
	now := time.Now()
	if now.Before(e.negUntil) {
		return "", true, true
	}
	if e.name != "" && now.Before(e.expiresAt) {
		return e.name, true, false
	}
	return "", false, false
}

func asNameCacheSet(asn int, name string, ttl time.Duration) {
	asNameCache.mu.Lock()
	defer asNameCache.mu.Unlock()
	asNameCache.m[asn] = &asNameCacheEntry{name: name, expiresAt: time.Now().Add(ttl)}
}

func asNameCacheNeg(asn int, ttl time.Duration) {
	asNameCache.mu.Lock()
	defer asNameCache.mu.Unlock()
	e := asNameCache.m[asn]
	if e == nil {
		e = &asNameCacheEntry{}
		asNameCache.m[asn] = e
	}
	e.negUntil = time.Now().Add(ttl)
}

func newCacheStore() *cacheStore { return &cacheStore{m: map[string]cacheEntry{}} }

func (c *cacheStore) get(key string) (APIResp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return APIResp{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.m, key)
		return APIResp{}, false
	}
	return e.val, true
}

func (c *cacheStore) set(key string, val APIResp, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{val: val, expiresAt: time.Now().Add(ttl)}
}

type rlStore struct {
	mu sync.Mutex
	m  map[string]*rlBucket
}
type rlBucket struct {
	windowStart time.Time
	count       int
}

func newRL() *rlStore { return &rlStore{m: map[string]*rlBucket{}} }

func (r *rlStore) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b, ok := r.m[key]
	if !ok {
		r.m[key] = &rlBucket{windowStart: now, count: 1}
		return true
	}
	if now.Sub(b.windowStart) >= time.Minute {
		b.windowStart = now
		b.count = 1
		return true
	}
	if b.count >= RateLimitPerMin {
		return false
	}
	b.count++
	return true
}

var (
	cache = newCacheStore()
	rl    = newRL()
)

// ---------------------------
// vis-network local-first (server-cached) script
// Serves /vis-network.min.js. On first request, the server fetches from CDN and caches in memory.
// This avoids requiring users to place a local file, while keeping subsequent loads local/same-origin.
// ---------------------------

var visCache = struct {
	mu   sync.Mutex
	data []byte
	ct   string
	etag string
	at   time.Time
}{}

// ---------------------------

func handleVisNetwork(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

	// Serve cached
	visCache.mu.Lock()
	data := visCache.data
	ct := visCache.ct
	etag := visCache.etag
	visCache.mu.Unlock()

	if len(data) > 0 {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
			if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("Cache-Control", "public, max-age=604800") // 7d
		_, _ = w.Write(data)
		return
	}

	cdns := []string{
		"https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js",
		"https://unpkg.com/vis-network/standalone/umd/vis-network.min.js",
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for _, u := range cdns {
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "myip/1.0 (+vis-cache)")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || len(b) == 0 {
			lastErr = fmt.Errorf("cdn status %d", resp.StatusCode)
			continue
		}
		ct2 := resp.Header.Get("Content-Type")
		if ct2 == "" {
			ct2 = "application/javascript; charset=utf-8"
		}
		sum := sha1.Sum(b)
		etag2 := fmt.Sprintf("W/\"%x\"", sum[:])

		visCache.mu.Lock()
		visCache.data = b
		visCache.ct = ct2
		visCache.etag = etag2
		visCache.at = time.Now()
		visCache.mu.Unlock()

		w.Header().Set("Content-Type", ct2)
		w.Header().Set("ETag", etag2)
		w.Header().Set("Cache-Control", "public, max-age=604800")
		_, _ = w.Write(b)
		return
	}
	http.Error(w, "vis-network unavailable: "+fmt.Sprint(lastErr), http.StatusBadGateway)
}

// ---------------------------
// Server
// ---------------------------

// withSecurityHeaders adds a few safe default headers (does not break existing functionality).
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------
// HTTP helpers: gzip + ETag
// ---------------------------

type gzipResponseWriter struct {
	http.ResponseWriter
	w *gzip.Writer
}

func (g gzipResponseWriter) Write(b []byte) (int, error) { return g.w.Write(b) }

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		next.ServeHTTP(gzipResponseWriter{ResponseWriter: w, w: gz}, r)
	})
}

// writeJSONWithETag writes JSON with a stable ETag and supports If-None-Match (304).
// Caller should set Content-Type before calling.
func writeJSONWithETag(w http.ResponseWriter, r *http.Request, obj any) {
	b, err := json.Marshal(obj)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false,"errors":["encode failed"]}`))
		return
	}
	h := sha1.Sum(b)
	etag := fmt.Sprintf("%q", fmt.Sprintf("%x", h[:]))
	w.Header().Set("ETag", etag)
	w.Header().Add("Vary", "If-None-Match")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(b)
}

// corsMiddleware allows the frontend to be opened via file:// (origin "null") or other origins during local dev.
// It is intentionally permissive for /api/* endpoints only.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "index.html")
	})
	mux.HandleFunc("/api/ip", handleIP)
	mux.HandleFunc("/api/bgp", handleBGP)
	mux.HandleFunc("/api/health", handleHealth)

	mux.HandleFunc("/vis-network.min.js", handleVisNetwork)
	fmt.Printf("✅ 服务已启动: http://localhost%s\n", ListenAddr)
	_ = http.ListenAndServe(ListenAddr, corsMiddleware(gzipMiddleware(withSecurityHeaders(mux))))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	debug := r.URL.Query().Get("debug") == "1"

	type keyInfo struct {
		Configured bool   `json:"configured"`
		Source     string `json:"source"` // env/default/missing
		Note       string `json:"note,omitempty"`
	}

	// Never return raw secrets.
	get := func(envName string) string { return strings.TrimSpace(getEnv(envName)) }

	keys := map[string]keyInfo{}

	// ipapi.is: has built-in default key for convenience; env overrides default.
	if v := get("IPAPI_IS_KEY"); v != "" {
		keys["ipapi_is_key"] = keyInfo{Configured: true, Source: "env"}
	} else if defaultIPAPIIsKey != "" {
		keys["ipapi_is_key"] = keyInfo{Configured: true, Source: "default", Note: "using compiled-in default key"}
	} else {
		keys["ipapi_is_key"] = keyInfo{Configured: false, Source: "missing"}
	}

	// ipapi.org: only works when configured.
	if v := get("IPAPI_ORG_KEY"); v != "" {
		keys["ipapi_org_key"] = keyInfo{Configured: true, Source: "env"}
	} else if defaultIPAPIOrgKey != "" {
		// keep behavior consistent with your existing code which uses a default
		keys["ipapi_org_key"] = keyInfo{Configured: true, Source: "default", Note: "using compiled-in default key"}
	} else {
		keys["ipapi_org_key"] = keyInfo{Configured: false, Source: "missing"}
	}

	// ipinfo.io token
	if v := get("IPINFO_TOKEN"); v != "" {
		keys["ipinfo_token"] = keyInfo{Configured: true, Source: "env"}
	} else if strings.TrimSpace(defaultIPInfoToken) != "" {
		keys["ipinfo_token"] = keyInfo{Configured: true, Source: "default", Note: "using compiled-in default key"}
	} else {
		keys["ipinfo_token"] = keyInfo{Configured: false, Source: "missing"}
	}

	// ipdata.co key
	if v := get("IPDATA_KEY"); v != "" {
		keys["ipdata_key"] = keyInfo{Configured: true, Source: "env"}
	} else if strings.TrimSpace(defaultIPDataKey) != "" {
		keys["ipdata_key"] = keyInfo{Configured: true, Source: "default", Note: "using compiled-in default key"}
	} else {
		keys["ipdata_key"] = keyInfo{Configured: false, Source: "missing"}
	}

	out := map[string]any{
		"ok":   true,
		"time": time.Now().Format(time.RFC3339),
		"keys": keys,
		"stats": map[string]any{

			"domain_fallback": map[string]any{
				"asn_domain": map[string]uint64{
					"hit":  atomic.LoadUint64(&asnDomainFillHit),
					"miss": atomic.LoadUint64(&asnDomainFillMiss),
				},
				"org_domain": map[string]uint64{
					"hit":  atomic.LoadUint64(&orgDomainFillHit),
					"miss": atomic.LoadUint64(&orgDomainFillMiss),
				},
			},
		},
		"config": map[string]any{
			"listen_addr":          ListenAddr,
			"request_timeout_sec":  int(RequestTimeout.Seconds()),
			"per_call_timeout_sec": int(PerCallTimeout.Seconds()),
			"cache_ttl_sec":        int(CacheTTL.Seconds()),
			"rate_limit_per_min":   RateLimitPerMin,
		},
	}

	counts, last, lastTarget, lastReqTarget, lastReqAtUnix, lastReqSources := snapshotFieldSources()
	out["field_sources"] = counts
	out["field_sources_last"] = map[string]any{"target": lastTarget, "last": last}
	if debug {
		out["last_request_sources"] = map[string]any{"target": lastReqTarget, "at_unix": lastReqAtUnix, "sources": lastReqSources}
	}

	_ = json.NewEncoder(w).Encode(out)
}

// extractIPQueryInput accepts ONLY the normalized query format:
//
//	/api/ip?=1.2.3.4
//	/api/ip?=example.com
//
// It also supports a raw query without '=' for convenience:
//
//	/api/ip?1.2.3.4
func extractIPQueryInput(r *http.Request) string {
	// Primary: empty key
	input := strings.TrimSpace(r.URL.Query().Get(""))
	if input != "" {
		return input
	}
	// Secondary: raw query without '=' (e.g. "?1.2.3.4")
	raw := strings.TrimSpace(r.URL.RawQuery)
	if raw != "" && !strings.Contains(raw, "=") {
		return raw
	}
	return ""
}

func handleIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	clientIP := getClientIP(r)
	if clientIP == "" {
		clientIP = "unknown"
	}
	if !rl.allow(clientIP) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(APIResp{Ok: false, Errors: []string{"Too many requests"}})
		return
	}

	debug := r.URL.Query().Get("debug") == "1"
	// Normalized query format:
	//   /api/ip?=1.2.3.4
	//   /api/ip?=example.com
	input := extractIPQueryInput(r)
	target, dnsSource, err := resolveTargetIP(r, input)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResp{Ok: false, Errors: []string{err.Error()}})
		return
	}

	key := canonicalIPKey(target)

	if v, ok := cache.get(key); ok {
		_ = json.NewEncoder(w).Encode(v)
		return
	}

	// Fast path: non-public IP (e.g., 127.0.0.1 / LAN) — avoid slow external calls on first page load.
	parsed := net.ParseIP(target)
	if parsed == nil || !isPublicIP(parsed) {
		info := IPInfo{IP: target, Registry: ""}
		out := APIResp{
			Ok:   true,
			Data: info,
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	// -------- Unified synchronous mode (single-pass enrichment) --------
	// To reduce bugs caused by staged caching, we compute once per request and cache only the final merged result.
	ctx, cancel := context.WithTimeout(r.Context(), RequestTimeout)
	defer cancel()

	resp := computeFull(ctx, target, input, debug, dnsSource)
	// Cache final result only (keyed by IP). For domain/URL queries we still cache by resolved IP.
	cache.set(key, resp, CacheTTL)

	// Strip optional fields unless debug=1 (keep errors for ok=false)
	if !debug && resp.Ok {
		resp.Errors = nil
	}

	_ = json.NewEncoder(w).Encode(resp)
	return

}

// handleDomain fills only domain-related fields (asn_domain / org_domain / flag_img) best-effort.
// It is designed to be called by the frontend after first paint, without re-running full enrichment.

// handleMyIPRedirect keeps backward compatibility for old clients.
// It parses legacy query styles and issues a permanent redirect to the normalized endpoint: /api/ip?=...

// handleMyIP is kept as a small compatibility wrapper (internal).
func handleMyIP(w http.ResponseWriter, r *http.Request) { handleIP(w, r) }

// handleBGP provides BGP topology as a separate, lazy-loaded endpoint.
// Usage:
//   /api/bgp?asn=12345
//   /api/bgp?ip=1.2.3.4
//   /api/bgp?q=example.com

// computeFull computes the full response (slow path) and writes it into cache.
// It is safe to call from both request handlers and background goroutines.

func computeFull(ctx context.Context, target string, input string, debug bool, dnsSource string) APIResp {
	// Unified synchronous path: compute once per request; no staged caching.
	base := IPInfo{IP: target, Registry: ""}

	// Primary source (ipapi.is) is called inside computeFullHeavy so errors can be recorded.

	// Heavy fields + multi-source best-effort fills.
	return computeFullHeavy(ctx, target, input, debug, dnsSource, base)
}

func mergeNonEmptyIPInfo(dst *IPInfo, src IPInfo) {
	// Fill only when dst is empty and src is meaningfully non-empty.
	// This prevents any provider from overwriting a good geo value with an empty/placeholder one.
	nonEmpty := func(v string) bool {
		vv := strings.TrimSpace(v)
		if vv == "" {
			return false
		}
		// Some upstreams may return placeholders like "-".
		if vv == "-" || strings.EqualFold(vv, "n/a") || strings.EqualFold(vv, "unknown") {
			return false
		}
		return true
	}
	setS := func(dstp *string, v string) {
		if !nonEmpty(*dstp) && nonEmpty(v) {
			*dstp = v
		}
	}

	// Geo
	setS(&dst.Country, src.Country)
	setS(&dst.CountryCode, src.CountryCode)
	setS(&dst.City, src.City)
	if dst.Lat == 0 && src.Lat != 0 {
		dst.Lat = src.Lat
	}
	if dst.Lon == 0 && src.Lon != 0 {
		dst.Lon = src.Lon
	}

	// ASN/Org
	setS(&dst.ASN, src.ASN)
	setS(&dst.ASNOwner, src.ASNOwner)
	setS(&dst.Org, src.Org)
	setS(&dst.ISP, src.ISP)

	// Domain-related
	setS(&dst.AsnDomain, src.AsnDomain)
	setS(&dst.OrgDomain, src.OrgDomain)

	// Registry fields: allow override of placeholder
	if nonEmpty(src.Registry) && strings.TrimSpace(src.Registry) != "Global Registry" {
		if !nonEmpty(dst.Registry) || strings.TrimSpace(dst.Registry) == "Global Registry" {
			dst.Registry = src.Registry
		}
	}
	setS(&dst.RegRegion, src.RegRegion)

	// Keep first non-empty sources (internal markers)
	setS(&dst.ASNOwnerSource, src.ASNOwnerSource)
	setS(&dst.OrgSource, src.OrgSource)
	setS(&dst.AsnDomainSource, src.AsnDomainSource)
	setS(&dst.OrgDomainSource, src.OrgDomainSource)
}

func computeFullHeavy(ctx context.Context, target string, input string, debug bool, dnsSource string, base IPInfo) APIResp {
	httpc := httpClientFull
	errs := make([]string, 0, 10)

	resp := APIResp{
		Ok:   true,
		Data: base,
	}

	// Ensure base fields
	if strings.TrimSpace(resp.Data.IP) == "" {
		resp.Data.IP = target
	}

	nonEmpty := func(v string) bool {
		vv := strings.TrimSpace(v)
		if vv == "" {
			return false
		}
		if vv == "-" || strings.EqualFold(vv, "n/a") || strings.EqualFold(vv, "unknown") {
			return false
		}
		return true
	}

	// ---------------------------
	// Provider priority matrix (lower rank = higher priority)
	// ---------------------------
	rankGeo := makeRankMap(ProviderPriorityOrder[prioGeo])
	rankASN := makeRankMap(ProviderPriorityOrder[prioASN])
	rankOrg := makeRankMap(ProviderPriorityOrder[prioOrg])
	rankISP := makeRankMap(ProviderPriorityOrder[prioISP])
	rankAsnDomain := makeRankMap(ProviderPriorityOrder[prioAsnDomain])
	rankOrgDomain := makeRankMap(ProviderPriorityOrder[prioOrgDomain])
	rankRegistry := makeRankMap(ProviderPriorityOrder[prioRegistry])

	fieldSrc := map[string]string{}

	getRank := func(field string, provider string) int {
		if provider == "" {
			provider = "*"
		}
		switch field {
		case "country", "country_code", "city", "lat", "lon":
			if v, ok := rankGeo[provider]; ok {
				return v
			}
			return rankGeo["*"]
		case "asn", "asn_owner":
			if v, ok := rankASN[provider]; ok {
				return v
			}
			return rankASN["*"]
		case "org":
			if v, ok := rankOrg[provider]; ok {
				return v
			}
			return rankOrg["*"]
		case "isp":
			if v, ok := rankISP[provider]; ok {
				return v
			}
			return rankISP["*"]
		case "asn_domain":
			if v, ok := rankAsnDomain[provider]; ok {
				return v
			}
			return rankAsnDomain["*"]
		case "org_domain":
			if v, ok := rankOrgDomain[provider]; ok {
				return v
			}
			return rankOrgDomain["*"]
		case "registry", "reg_region":
			if v, ok := rankRegistry[provider]; ok {
				return v
			}
			return rankRegistry["*"]
		default:
			return 999999
		}
	}

	shouldSet := func(field string, provider string) bool {
		old := fieldSrc[field]
		return getRank(field, provider) < getRank(field, old)
	}

	setText := func(field string, dstp *string, v string, provider string) {
		if !nonEmpty(v) {
			return
		}
		// Registry placeholder is treated as empty.
		if field == "registry" && strings.TrimSpace(v) == "Global Registry" {
			return
		}
		if !nonEmpty(*dstp) {
			*dstp = v
			fieldSrc[field] = provider
			return
		}
		if shouldSet(field, provider) {
			*dstp = v
			fieldSrc[field] = provider
		}
	}

	setFloat := func(field string, dstp *float64, v float64, provider string) {
		if v == 0 {
			return
		}
		if *dstp == 0 {
			*dstp = v
			fieldSrc[field] = provider
			return
		}
		if shouldSet(field, provider) {
			*dstp = v
			fieldSrc[field] = provider
		}
	}

	mergePatch := func(p IPInfo, provider string) {
		// Normalize ASN early to keep downstream consistent.
		p.ASN = normalizeASN(p.ASN)

		setText("country", &resp.Data.Country, p.Country, provider)
		setText("country_code", &resp.Data.CountryCode, strings.ToUpper(p.CountryCode), provider)
		setText("city", &resp.Data.City, p.City, provider)
		setFloat("lat", &resp.Data.Lat, p.Lat, provider)
		setFloat("lon", &resp.Data.Lon, p.Lon, provider)

		setText("asn", &resp.Data.ASN, p.ASN, provider)
		setText("asn_owner", &resp.Data.ASNOwner, p.ASNOwner, provider)
		if fieldSrc["asn_owner"] == provider && strings.TrimSpace(p.ASNOwnerSource) != "" {
			resp.Data.ASNOwnerSource = p.ASNOwnerSource
		}

		setText("org", &resp.Data.Org, p.Org, provider)
		if fieldSrc["org"] == provider && strings.TrimSpace(p.OrgSource) != "" {
			resp.Data.OrgSource = p.OrgSource
		}

		setText("isp", &resp.Data.ISP, p.ISP, provider)

		// Domains (keep current source logic; only priority decides overwrites)
		setText("asn_domain", &resp.Data.AsnDomain, p.AsnDomain, provider)
		if fieldSrc["asn_domain"] == provider && strings.TrimSpace(p.AsnDomainSource) != "" {
			resp.Data.AsnDomainSource = p.AsnDomainSource
		}

		setText("org_domain", &resp.Data.OrgDomain, p.OrgDomain, provider)
		if fieldSrc["org_domain"] == provider && strings.TrimSpace(p.OrgDomainSource) != "" {
			resp.Data.OrgDomainSource = p.OrgDomainSource
		}

		setText("registry", &resp.Data.Registry, p.Registry, provider)
		setText("reg_region", &resp.Data.RegRegion, strings.ToUpper(p.RegRegion), provider)
	}

	runStep := func(s ProviderStep) {
		if s.when != nil && !s.when(resp.Data) {
			return
		}
		ctxP, cancel := context.WithTimeout(ctx, s.timeout)
		defer cancel()

		var patch IPInfo
		if s.fill != nil {
			patch = IPInfo{IP: resp.Data.IP}
			if err := s.fill(ctxP, s.client, &patch); err != nil {
				errs = append(errs, s.name+": "+err.Error())
				return
			}
		} else if s.fetch != nil {
			p, err := s.fetch(ctxP, s.client, resp.Data.IP)
			if err != nil {
				errs = append(errs, s.name+": "+err.Error())
				return
			}
			patch = p
		} else {
			return
		}
		mergePatch(patch, s.name)
	}

	steps := BuildProviderSteps(httpc, httpClientIPAPIIs)

	for _, s := range steps {
		runStep(s)
	}

	// Hard guarantee: do not leave these empty for first paint
	if strings.TrimSpace(resp.Data.Registry) == "" {
		resp.Data.Registry = "Global Registry"
	}
	if strings.TrimSpace(resp.Data.RegRegion) == "" {
		if strings.TrimSpace(resp.Data.CountryCode) != "" {
			resp.Data.RegRegion = strings.ToUpper(resp.Data.CountryCode)
		} else {
			resp.Data.RegRegion = "-"
		}
	}

	// Final normalize
	resp.Data.ASN = normalizeASN(resp.Data.ASN)

	// ---------------------------
	// Derived fields for UI (IP来源 / IP属性 / 人机流量比 / 风险分)
	// These must be computed on the final merged data; otherwise the frontend shows '-'.
	// ---------------------------
	// 1) IP来源
	resp.Data.IPSource, resp.Data.IPSourceReason = calcIPSourceDetailed(resp.Data)
	// 2) IP属性
	resp.Data.IPProperty, resp.Data.IPPropertyScores, resp.Data.IPPropertyReason = calcIPPropertyDetailed(resp.Data)
	// 3) 人机流量比
	{
		h, b, bd, reason := computeHumanBotDetailed(resp.Data)
		resp.Data.HumanPercent = h
		resp.Data.BotPercent = b
		resp.Data.HumanBotBreakdown = bd
		resp.Data.HumanBotReason = reason
		resp.Data.HumanBotConfidence = computeHumanBotConfidence(resp.Data, bd)
	}
	// 4) 风险分（需要先有 IP来源/IP属性 才能正确加权）
	{
		asnCountry := strings.ToUpper(strings.TrimSpace(resp.Data.RegRegion))
		if asnCountry == "-" {
			asnCountry = ""
		}
		prefixCountry := strings.ToUpper(strings.TrimSpace(resp.Data.CountryCode))
		score, breakdown, reason := computeRiskScoreDetailed(resp.Data, asnCountry, prefixCountry)
		resp.Data.RiskScore = score
		resp.Data.RiskBreakdown = breakdown
		resp.Data.RiskReason = reason
		resp.Data.RiskConfidence = computeRiskConfidence(resp.Data, breakdown)
	}

	// output debug errors
	if debug && len(errs) > 0 {
		resp.Errors = errs
	}
	return resp
}

// minimalBGPTopology returns a schema-compatible minimal BGP payload.
// This is used on fast-path timeouts/errors so the frontend can still render
// a stable center node + external links (instead of treating it as "no data").
func minimalBGPTopology(asn int) *BGPTopology {
	if asn <= 0 {
		return nil
	}
	return &BGPTopology{
		ASN:    asn,
		Name:   "",
		Source: "RIPEstat",
		ExternalLinks: map[string]string{
			"bgp_tools": fmt.Sprintf("https://bgp.tools/as/%d#connectivity", asn),
			"bgp_he":    fmt.Sprintf("https://bgp.he.net/AS%d#_graph4", asn),
		},
	}
}

func fillDomainsFast(ctx context.Context, httpc *http.Client, info *IPInfo, errs *[]string) {
	// Fast domain fill stage: only fill AsnDomain/OrgDomain.
	// Each upstream call has its own short timeout to prevent dragging the whole pipeline.
	needAsn := strings.TrimSpace(info.AsnDomain) == ""
	needOrg := strings.TrimSpace(info.OrgDomain) == ""

	if needAsn {
		ctx1, cancel1 := context.WithTimeout(ctx, DomainPerCallTimeout)
		defer cancel1()
		if err := fillFromIPInfoIO(ctx1, httpc, info); err != nil && !errors.Is(err, errNoAPIKey) {
			// Silent on short-timeout failures; domain fill is best-effort.
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				*errs = append(*errs, "ipinfo.io: "+err.Error())
			}
		}
	}
	if needAsn {
		ctx2, cancel2 := context.WithTimeout(ctx, DomainPerCallTimeout)
		defer cancel2()
		if err := fillFromIPDataCo(ctx2, httpc, info); err != nil && !errors.Is(err, errNoAPIKey) {
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				*errs = append(*errs, "ipdata.co: "+err.Error())
			}
		}
	}
	if needOrg {
		// IMPORTANT: fillFromIPWho historically could overwrite geo. We rely on its internal merge rules
		// (non-empty -> fill empty) to keep geo stable. This stage is only for domain/flag.
		ctx3, cancel3 := context.WithTimeout(ctx, DomainPerCallTimeout)
		defer cancel3()
		if err := fillFromIPWho(ctx3, httpc, info); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				*errs = append(*errs, "ipwho.is: "+err.Error())
			}
		}
	}
}

func handleBGP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	send := func(payload map[string]any) {
		writeJSONWithETag(w, r, payload)
	}

	// Light rate-limit (shared bucket is fine)
	clientIP := getClientIP(r)
	if clientIP == "" {
		clientIP = "unknown"
	}
	if !rl.allow(clientIP) {
		w.WriteHeader(http.StatusTooManyRequests)
		send(map[string]any{"ok": false, "error": "Too many requests"})
		return
	}

	// Parse ASN: ?asn=AS123 or resolve from ?ip= / ?q= / raw query
	q := strings.TrimSpace(r.URL.Query().Get("asn"))
	var asnNum int
	var err error
	var target string
	var rerr error
	if q != "" {
		q = strings.TrimPrefix(strings.ToUpper(q), "AS")
		asnNum, err = strconv.Atoi(q)
		if err != nil || asnNum <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			send(map[string]any{"ok": false, "error": "invalid asn"})
			return
		}
	} else {
		input := strings.TrimSpace(r.URL.Query().Get("ip"))
		if input == "" {
			input = strings.TrimSpace(r.URL.Query().Get("q"))
		}
		if input == "" {
			input = strings.TrimSpace(r.URL.Query().Get(""))
		}
		if input == "" {
			raw := strings.TrimSpace(r.URL.RawQuery)
			if raw != "" && !strings.Contains(raw, "=") {
				input = raw
			}
		}

		target, _, rerr = resolveTargetIP(r, input)
		if rerr != nil {
			w.WriteHeader(http.StatusBadRequest)
			send(map[string]any{"ok": false, "error": rerr.Error()})
			return
		}

		// Resolve ASN from IP (not RIPEstat BGP)
		ctx := r.Context()
		httpc := httpClientFull

		tmp := IPInfo{IP: target}
		_ = fillFromIPApiIs(ctx, httpClientIPAPIIs, &tmp)
		if strings.TrimSpace(tmp.ASN) == "" {
			_ = fillFromIPWho(ctx, httpc, &tmp)
		}
		if strings.TrimSpace(tmp.ASN) == "" {
			_ = fillFromIPAPICom(ctx, httpc, &tmp)
		}
		if strings.TrimSpace(tmp.ASN) == "" {
			_ = fillFromIPApiOrg(ctx, httpc, &tmp)
		}
		tmp.ASN = normalizeASN(tmp.ASN)
		asnStr := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(tmp.ASN)), "AS")
		asnNum, err = strconv.Atoi(asnStr)
		if err != nil || asnNum <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			send(map[string]any{"ok": false, "error": "asn not found"})
			return
		}
	}

	// limit=N: return up to N upstream ASNs. Default 80, clamp 1..300.
	limit := 80
	if ls := strings.TrimSpace(r.URL.Query().Get("limit")); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 300 {
		limit = 300
	}

	// Serve cache if available; refresh stale in background (no 'loading' status / polling).
	if v, state, _, _ := bgpTopoGetMeta(asnNum); state > 0 && v != nil {
		if state == 1 {
			// stale
			if !bgpTopoIsRefreshing(asnNum) {
				if bgpTopoTryMarkRefreshing(asnNum) {
					go func(asn int) {
						defer bgpTopoUnmarkRefreshing(asn)
						fullClient := *httpClientBGPFull
						ctxBG, cancel := context.WithTimeout(context.Background(), 45*time.Second)
						defer cancel()
						topo2, err2 := fetchBGPTopologyCap(ctxBG, &fullClient, asn, limit)
						if err2 == nil && topo2 != nil && len(topo2.Upstreams) > 0 {
							bgpTopoSet(asn, topo2, 10*time.Minute, 24*time.Hour)
							return
						}
						if err2 != nil {
							bgpTopoSetErr(asn, "ripestat(asn-neighbours): "+err2.Error())
						} else {
							bgpTopoSetErr(asn, "ripestat(asn-neighbours): empty")
						}
					}(asnNum)
				}
			}
			send(map[string]any{
				"ok":    true,
				"asn":   asnNum,
				"data":  limitBGPTopologyPerDir(v, limit),
				"stale": true,
			})
			return
		}

		// fresh
		send(map[string]any{
			"ok":   true,
			"asn":  asnNum,
			"data": limitBGPTopologyPerDir(v, limit),
		})
		return
	}

	// True miss: synchronous fetch once, return error on failure (no polling).
	fastClient := *httpClientBGPFast
	topo, errTopo := fetchBGPTopologyCap(r.Context(), &fastClient, asnNum, limit)
	if errTopo == nil && topo != nil && len(topo.Upstreams) > 0 {
		bgpTopoSet(asnNum, topo, 10*time.Minute, 24*time.Hour)
		send(map[string]any{
			"ok":   true,
			"asn":  asnNum,
			"data": limitBGPTopologyPerDir(topo, limit),
		})
		return
	}

	// miss + error
	if errTopo != nil {
		bgpTopoSetErr(asnNum, "ripestat(asn-neighbours): "+errTopo.Error())
	}
	// Return 200 with ok=false to avoid browser console 502 noise; front-end renders error from payload.
	// (This endpoint is best-effort and should not hard-fail HTTP level.)
	send(map[string]any{
		"ok":             false,
		"status":         "error",
		"http_status":    200,
		"asn":            asnNum,
		"error":          "ripestat(asn-neighbours) failed",
		"external_links": minimalBGPTopology(asnNum).ExternalLinks,
	})
}

func limitBGPTopologyPerDir(t *BGPTopology, limit int) *BGPTopology {
	if t == nil || limit <= 0 {
		return t
	}
	out := *t
	if out.Upstreams != nil {
		out.Upstreams = append([]ASNNode(nil), out.Upstreams...)
		if len(out.Upstreams) > limit {
			out.Upstreams = out.Upstreams[:limit]
		}
	}
	// external_links map is read-only in our usage; keep as-is.
	return &out
}

// ---------------------------
// Client IP / Resolve
// ---------------------------

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		first := strings.TrimSpace(parts[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	xri := r.Header.Get("X-Real-IP")
	if xri != "" && net.ParseIP(strings.TrimSpace(xri)) != nil {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	return ""
}

func resolveTargetIP(r *http.Request, input string) (string, string, error) {
	// Returns: resolvedIP, dnsSource, error
	// dnsSource values:
	//   - direct_ip: input is already an IP
	//   - client_ip: input empty -> use client IP
	//   - doh_cloudflare / doh_google: resolved via DoH providers
	//   - cache:<provider>: resolved from DNS cache
	if input == "" {
		ip := getClientIP(r)
		if DevFallbackToServerPublicIP && (ip == "" || isLoopbackOrPrivate(ip)) {
			pub, err := getServerPublicIP(r.Context())
			if err == nil && pub != "" {
				return pub, "server_public_ip", nil
			}
			return "8.8.8.8", "server_public_ip", nil
		}
		if ip == "" {
			return "", "", errors.New("无法识别来访者 IP")
		}
		return ip, "client_ip", nil
	}

	if strings.HasPrefix(strings.ToLower(input), "http://") || strings.HasPrefix(strings.ToLower(input), "https://") {
		u, err := url.Parse(input)
		if err == nil && u.Hostname() != "" {
			input = u.Hostname()
		}
	}

	if net.ParseIP(input) != nil {
		return input, "direct_ip", nil
	}

	if len(input) > 253 || !domainRe.MatchString(input) {
		return "", "", errors.New("请输入合法 IP / 域名 / URL")
	}

	// DoH-only (system DNS may be hijacked). Use DNS cache + concurrent providers.
	ip, src, err := dohResolveFast(r.Context(), input)
	if err != nil || ip == "" {
		if err == nil {
			err = errors.New("doh: no public answer")
		}
		return "", "", err
	}
	return ip, src, nil
}

func isLoopbackOrPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() {
		return true
	}
	privateBlocks := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	}
	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(parsed) {
			return true
		}
	}
	return false
}

// isPublicIP reports whether ip is a public (non-private, non-loopback) address.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// Exclude RFC1918, ULA, and link-local.
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

type dohAnswer struct {
	Data string `json:"data"`
	Type int    `json:"type,omitempty"`
}

type dohResp struct {
	Answer []dohAnswer `json:"Answer"`
}

// ---------------------------
// DoH-only DNS resolver (concurrent providers + small TTL cache)
// ---------------------------

type dnsCacheEntry struct {
	ip        string
	source    string
	expiresAt time.Time
}

var dnsCache = struct {
	mu sync.Mutex
	m  map[string]dnsCacheEntry
}{m: map[string]dnsCacheEntry{}}

const DNSCacheTTL = 60 * time.Second

// Shared DoH HTTP client (keep-alive, low overhead)
var dohHTTPClient = &http.Client{
	Timeout: PerCallTimeout,
	Transport: &http.Transport{
		Proxy: nil, // disable env/system proxy for DoH
		// (avoids local proxy/MITM causing inconsistent DNS answers)

		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

func dnsCacheGet(domain string) (string, string, bool) {
	k := strings.ToLower(strings.TrimSpace(domain))
	if k == "" {
		return "", "", false
	}
	now := time.Now()
	dnsCache.mu.Lock()
	defer dnsCache.mu.Unlock()
	e, ok := dnsCache.m[k]
	if !ok || now.After(e.expiresAt) || e.ip == "" {
		if ok && now.After(e.expiresAt) {
			delete(dnsCache.m, k)
		}
		return "", "", false
	}
	return e.ip, e.source, true
}

func dnsCacheSet(domain, ip, source string, ttl time.Duration) {
	k := strings.ToLower(strings.TrimSpace(domain))
	if k == "" || ip == "" {
		return
	}
	dnsCache.mu.Lock()
	dnsCache.m[k] = dnsCacheEntry{
		ip:        ip,
		source:    source,
		expiresAt: time.Now().Add(ttl),
	}
	dnsCache.mu.Unlock()
}

type dohProvider struct {
	name string
	urlT string // sprintf with name,type
	hdr  map[string]string
}

var dohPrimaryProviders = []dohProvider{
	{
		name: "doh_cloudflare",
		urlT: "https://cloudflare-dns.com/dns-query?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
	{
		name: "doh_google",
		urlT: "https://dns.google/resolve?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
	{
		name: "doh_quad9",
		urlT: "https://9.9.9.9/dns-query?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
}

var dohFallbackProviders = []dohProvider{
	{
		name: "doh_aliyun_223",
		urlT: "https://223.5.5.5/dns-query?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
	{
		name: "doh_pub",
		urlT: "https://doh.pub/dns-query?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
	{
		name: "doh_apad",
		urlT: "https://doh.apad.pro/dns-query?name=%s&type=%s",
		hdr:  map[string]string{"Accept": "application/dns-json"},
	},
}

// dohResolveFast resolves a domain to a *public* IP using DoH only, with:
// - small TTL cache (domain -> ip)
// - concurrent public DoH providers (region-dependent), first successful wins
// Returns (ip, dnsSource, error)
func dohResolveFast(parent context.Context, domain string) (string, string, error) {
	// Fast path: cache
	if ip, src, ok := dnsCacheGet(domain); ok {
		return ip, "cache:" + src, nil
	}

	// First-win concurrent DoH with preferred providers; no retries.
	tryProviders := func(providers []dohProvider, timeout time.Duration) (string, string, error) {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()

		type result struct {
			ip  string
			src string
			err error
		}
		ch := make(chan result, len(providers))

		for _, p := range providers {
			p := p
			go func() {
				ip, err := dohResolveProvider(ctx, domain, p)
				ch <- result{ip: ip, src: p.name, err: err}
			}()
		}

		var lastErr error
		for i := 0; i < len(providers); i++ {
			res := <-ch
			if res.err == nil && res.ip != "" {
				// cache provider result (without cache: prefix)
				dnsCacheSet(domain, res.ip, res.src, DNSCacheTTL)
				return res.ip, res.src, nil
			}
			if res.err != nil {
				lastErr = res.err
			}
		}
		if lastErr == nil {
			lastErr = errors.New("doh: no public answer")
		}
		return "", "", lastErr
	}

	// Primary providers (fast, reliable in your environment)
	ip, src, err := tryProviders(dohPrimaryProviders, 800*time.Millisecond)
	if err == nil && ip != "" {
		return ip, src, nil
	}

	// Fallback providers (still DoH-only)
	ip, src, err2 := tryProviders(dohFallbackProviders, 1200*time.Millisecond)
	if err2 == nil && ip != "" {
		return ip, src, nil
	}

	// Preserve most relevant error message.
	if err2 != nil {
		return "", "", err2
	}
	return "", "", err
}

func dohResolveProvider(ctx context.Context, domain string, p dohProvider) (string, error) {
	// Prefer A, fallback AAAA, with CNAME chase (limited depth).
	return dohResolveProviderDepth(ctx, domain, p, 0)
}

const maxCNAMEChaseDepth = 6

func dohResolveProviderDepth(ctx context.Context, domain string, p dohProvider, depth int) (string, error) {
	if depth > maxCNAMEChaseDepth {
		return "", errors.New("doh: cname chase limit")
	}

	// Try A first
	if ip, cname, err := dohResolveType(ctx, domain, "A", p); err == nil && ip != "" {
		return ip, nil
	} else if ip == "" && cname != "" {
		// Chase CNAME (normalize trailing dot)
		cname = strings.TrimSuffix(strings.TrimSpace(cname), ".")
		if cname != "" && !strings.EqualFold(cname, domain) {
			if rip, err2 := dohResolveProviderDepth(ctx, cname, p, depth+1); err2 == nil && rip != "" {
				return rip, nil
			}
		}
	}

	// Then AAAA
	if ip, cname, err := dohResolveType(ctx, domain, "AAAA", p); err == nil && ip != "" {
		return ip, nil
	} else if ip == "" && cname != "" {
		cname = strings.TrimSuffix(strings.TrimSpace(cname), ".")
		if cname != "" && !strings.EqualFold(cname, domain) {
			if rip, err2 := dohResolveProviderDepth(ctx, cname, p, depth+1); err2 == nil && rip != "" {
				return rip, nil
			}
		}
	}

	return "", errors.New("doh: no public answer")
}

// dohResolveType queries one qtype and returns:
// - ip: first public IP found (v4 preferred by caller, but we just return first match encountered; caller orders types)
// - cname: first CNAME target observed (best-effort), used for CNAME chasing
func dohResolveType(ctx context.Context, domain, qtype string, p dohProvider) (ipOut string, cnameOut string, err error) {
	u := fmt.Sprintf(p.urlT, url.QueryEscape(domain), qtype)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "myip/1.0 (+doh)")
	for k, v := range p.hdr {
		req.Header.Set(k, v)
	}
	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var dr dohResp
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return "", "", err
	}

	var v6 string
	for _, a := range dr.Answer {
		data := strings.TrimSpace(a.Data)
		if data == "" {
			continue
		}
		// CNAME type is 5 in DNS records; keep first CNAME target for chasing.
		if cnameOut == "" && (a.Type == 5 || (net.ParseIP(data) == nil && strings.Contains(data, ".") && strings.HasSuffix(data, "."))) {
			cnameOut = data
			continue
		}

		ip := net.ParseIP(data)
		if ip == nil || !isPublicIP(ip) {
			continue
		}
		if ip.To4() != nil {
			return ip.String(), cnameOut, nil
		}
		if v6 == "" {
			v6 = ip.String()
		}
	}
	if v6 != "" {
		return v6, cnameOut, nil
	}
	// No IP in this answer set, but might have CNAME.
	if cnameOut != "" {
		return "", cnameOut, errors.New("doh: cname")
	}
	return "", "", errors.New("doh: empty")
}

func getServerPublicIP(ctx context.Context) (string, error) {
	u := "https://api64.ipify.org?format=json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	c := httpClientFull
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ipify http %d", resp.StatusCode)
	}
	var d struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", err
	}
	if net.ParseIP(d.IP) == nil {
		return "", errors.New("invalid ip from ipify")
	}
	return d.IP, nil
}

// ---------------------------
// Registry (RIR) + Registered Country
// ---------------------------

// ripeRIRAndCountry queries RIPEstat's "rir" endpoint, which is derived from
// the RIR delegation statistics files. This is the closest thing to
// “注册局/注册国别” and is intentionally different from geo-location country.
func ripeRIRAndCountry(ctx context.Context, c *http.Client, ip string) (rir string, regCC string, err error) {
	// lod=2 generally includes country information.
	u := fmt.Sprintf("https://stat.ripe.net/data/rir/data.json?resource=%s&lod=2", url.QueryEscape(ip))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("http %d", resp.StatusCode)
	}

	// Use loose parsing to tolerate minor schema changes.
	var root struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return "", "", err
	}
	if root.Data == nil {
		return "", "", errors.New("empty data")
	}

	// Typical shape: data.rirs: [{"rir":"ARIN","country":"US","resource":"216.238.52.0/24",...}]
	if arr, ok := root.Data["rirs"].([]any); ok && len(arr) > 0 {
		bestRIR, bestCC := "", ""
		bestScore := -1
		for _, it := range arr {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			candRIR, _ := m["rir"].(string)
			candCC, _ := m["country"].(string)
			candRes, _ := m["resource"].(string)
			score := scoreResourceSpecificity(candRes)
			if score > bestScore {
				bestScore = score
				bestRIR = candRIR
				bestCC = candCC
			}
		}
		return strings.TrimSpace(bestRIR), strings.TrimSpace(bestCC), nil
	}

	// Fallbacks for alternative shapes.
	if v, ok := root.Data["rir"].(string); ok {
		rir = strings.TrimSpace(v)
	}
	if v, ok := root.Data["country"].(string); ok {
		regCC = strings.TrimSpace(v)
	}
	if rir == "" && regCC == "" {
		return "", "", errors.New("no rir/country in response")
	}
	return rir, regCC, nil
}

// normalizeCountryCode keeps only ISO-3166-1 alpha-2 country codes (e.g. "US", "JP").
// Anything else returns empty.

func isMeaningfulString(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	switch strings.ToLower(s) {
	case "-", "n/a", "na", "none", "null", "unknown", "undefined":
		return false
	default:
		return true
	}
}

func normalizeCountryCode(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		return ""
	}
	for _, r := range cc {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return cc
}

// rdapCountry queries an RDAP endpoint and tries to read the registered country.
// We intentionally only use registration/registry country fields, NOT geo.
func rdapCountry(ctx context.Context, c *http.Client, baseURL string, ip string) (string, error) {
	u := strings.TrimRight(baseURL, "/") + "/" + url.PathEscape(ip)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}

	var root map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return "", err
	}

	// 1) Many RDAP servers expose "country" at top-level for IP networks.
	if v, ok := root["country"].(string); ok {
		if cc := normalizeCountryCode(v); cc != "" {
			return cc, nil
		}
	}

	// 2) Some expose "country" under "network".
	if netObj, ok := root["network"].(map[string]any); ok {
		if v, ok := netObj["country"].(string); ok {
			if cc := normalizeCountryCode(v); cc != "" {
				return cc, nil
			}
		}
	}

	// 3) As a fallback, walk entities and try to find a country code from vCard addresses.
	// RDAP entity.vcardArray often contains:
	// ["vcard", [ ["fn",{}, "text","..."], ["adr",{}, "text", ["","","","","","<CC>"]] ... ]]
	if ents, ok := root["entities"].([]any); ok {
		for _, e := range ents {
			ent, _ := e.(map[string]any)
			if ent == nil {
				continue
			}
			cc := rdapCountryFromVCard(ent)
			if cc != "" {
				return cc, nil
			}
		}
	}

	return "", errors.New("no country in rdap response")
}

func rdapCountryFromVCard(ent map[string]any) string {
	vca, ok := ent["vcardArray"].([]any)
	if !ok || len(vca) < 2 {
		return ""
	}
	// vca[1] should be []any with card props
	props, ok := vca[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, _ := prop[0].(string)
		if strings.ToLower(name) != "adr" {
			continue
		}
		// prop[3] often is []any with address parts; last element may be country code/name
		switch v := prop[3].(type) {
		case []any:
			if len(v) == 0 {
				continue
			}
			last := v[len(v)-1]
			if s, ok := last.(string); ok {
				if cc := normalizeCountryCode(s); cc != "" {
					return cc
				}
			}
		case string:
			if cc := normalizeCountryCode(v); cc != "" {
				return cc
			}
		}
	}
	return ""
}

// whoisRegCountry tries to obtain allocation/registration country using WHOIS.
// It uses whois.iana.org to discover the authoritative WHOIS server, then queries that server.
// Missing/unknown fields never produce a hard error; we return empty strings in that case.
func whoisRegCountry(ctx context.Context, ip string) (whoisServer string, regCC string, err error) {
	// 1) Ask IANA for referral.
	ref, err := whoisQuery(ctx, "whois.iana.org:43", ip)
	if err != nil {
		return "", "", err
	}
	refServer := parseWhoisReferral(ref)
	if refServer == "" {
		return "", "", errors.New("iana: no referral")
	}
	// 2) Query the referred server.
	body, err := whoisQuery(ctx, net.JoinHostPort(refServer, "43"), ip)
	if err != nil {
		return refServer, "", err
	}
	cc := parseWhoisCountry(body)
	return refServer, cc, nil
}

func whoisQuery(ctx context.Context, addr string, q string) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	// RFC 3912: query + CRLF
	if _, err := conn.Write([]byte(q + "\r\n")); err != nil {
		return "", err
	}
	// Limit read size to avoid huge responses.
	const limit = 256 * 1024
	b, err := io.ReadAll(io.LimitReader(conn, limit))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseWhoisReferral(body string) string {
	// IANA typically returns: "refer: whois.arin.net"
	re := regexp.MustCompile(`(?im)^\s*refer:\s*([^\s]+)\s*$`)
	m := re.FindStringSubmatch(body)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	// Some formats: "whois: whois.apnic.net"
	re2 := regexp.MustCompile(`(?im)^\s*whois:\s*([^\s]+)\s*$`)
	m2 := re2.FindStringSubmatch(body)
	if len(m2) >= 2 {
		return strings.TrimSpace(m2[1])
	}
	return ""
}

func parseWhoisCountry(body string) string {
	// Take the first country-like field occurrence.
	// Common keys: country, Country, country-code.
	re := regexp.MustCompile(`(?im)^\s*(country|country-code)\s*:\s*([A-Za-z]{2})\s*$`)
	m := re.FindStringSubmatch(body)
	if len(m) >= 3 {
		if cc := normalizeCountryCode(m[2]); cc != "" {
			return cc
		}
	}
	// ARIN often uses "Country: US" (already covered), but sometimes appears in Org* fields.
	re2 := regexp.MustCompile(`(?im)^\s*Country\s*:\s*([A-Za-z]{2})\s*$`)
	m2 := re2.FindStringSubmatch(body)
	if len(m2) >= 2 {
		if cc := normalizeCountryCode(m2[1]); cc != "" {
			return cc
		}
	}
	return ""
}

func rirFromWhoisServer(s string) string {
	ls := strings.ToLower(s)
	switch {
	case strings.Contains(ls, "arin"):
		return "ARIN"
	case strings.Contains(ls, "ripe"):
		return "RIPE NCC"
	case strings.Contains(ls, "apnic"):
		return "APNIC"
	case strings.Contains(ls, "lacnic"):
		return "LACNIC"
	case strings.Contains(ls, "afrinic"):
		return "AFRINIC"
	default:
		return ""
	}
}

// registryFromRDAP tries multiple RDAP servers to identify registration country (and implied RIR).
func registryFromRDAP(ctx context.Context, c *http.Client, ip string) (rir string, regCC string, err error) {
	// Prefer RDAP.org bootstrapping; then cross-check with WHOIS referral from IANA.
	var rdapRIR, rdapCC string

	tests := []struct {
		rir  string
		base string
	}{
		{"RDAP.org", "https://rdap.org/ip"},
		{"ARIN", "https://rdap.arin.net/registry/ip"},
		{"RIPE NCC", "https://rdap.db.ripe.net/ip"},
		{"APNIC", "https://rdap.apnic.net/ip"},
		{"LACNIC", "https://rdap.lacnic.net/rdap/ip"},
		{"AFRINIC", "https://rdap.afrinic.net/rdap/ip"},
	}
	for _, t := range tests {
		cc, e := rdapCountry(ctx, c, t.base, ip)
		if e == nil && cc != "" {
			rdapRIR, rdapCC = t.rir, cc
			break
		}
	}

	// WHOIS fallback / cross-check (best-effort).
	whoisServer, whoisCC, werr := whoisRegCountry(ctx, ip)
	if werr == nil && whoisCC != "" {
		// Prefer WHOIS if RDAP missing, or if WHOIS disagrees (WHOIS is often closer to RIR DB text fields).
		if rdapCC == "" || whoisCC != rdapCC {
			rirGuess := rirFromWhoisServer(whoisServer)
			if rirGuess != "" {
				return rirGuess, whoisCC, nil
			}
			// Fallback to RDAP rir label if available.
			if rdapRIR != "" {
				return rdapRIR, whoisCC, nil
			}
			return "WHOIS", whoisCC, nil
		}
	}

	if rdapCC != "" {
		return rdapRIR, rdapCC, nil
	}
	if werr == nil && whoisCC != "" {
		rirGuess := rirFromWhoisServer(whoisServer)
		if rirGuess == "" {
			rirGuess = "WHOIS"
		}
		return rirGuess, whoisCC, nil
	}
	return "", "", errors.New("all rdap/whois methods failed")
}

func normalizeRIRName(rir string) string {
	// Make output consistent with your UI expectation: APNIC/ARIN/LACNIC/AFRINIC/RIPE NCC
	r := strings.TrimSpace(strings.ToLower(rir))
	switch {
	case r == "ripe" || strings.Contains(r, "ripe"):
		return "RIPE NCC"
	case strings.Contains(r, "rdap.org"):
		return "RDAP"
	case strings.Contains(r, "arin"):
		return "ARIN"
	case strings.Contains(r, "apnic"):
		return "APNIC"
	case strings.Contains(r, "lacnic"):
		return "LACNIC"
	case strings.Contains(r, "afrinic"):
		return "AFRINIC"
	default:
		// keep original if already looks good
		return strings.TrimSpace(rir)
	}
}

// registryBestEffort returns (RIR, registration_country_code) using a best-effort strategy.
// It intentionally focuses on "registration" (RIR/RDAP) rather than "usage location".
// Caller should provide a deadline via ctx.
func registryBestEffort(ctx context.Context, httpc *http.Client, ip string) (string, string, error) {
	type one struct{ rir, cc string }

	// Run RIPEstat and generic RDAP inference in parallel.
	riCh := make(chan one, 1)
	rdCh := make(chan one, 1)

	go func() {
		rir, cc, err := ripeRIRAndCountry(ctx, httpc, ip)
		if err == nil {
			riCh <- one{rir: normalizeRIRName(rir), cc: normalizeCountryCode(cc)}
			return
		}
		riCh <- one{}
	}()

	go func() {
		rir, cc, err := registryFromRDAP(ctx, httpc, ip)
		if err == nil {
			rdCh <- one{rir: normalizeRIRName(rir), cc: normalizeCountryCode(cc)}
			return
		}
		rdCh <- one{}
	}()

	best := one{}
	got := 0
	for got < 2 {
		select {
		case v := <-riCh:
			got++
			if best.rir == "" && v.rir != "" {
				best.rir = v.rir
			}
			if best.cc == "" && v.cc != "" {
				best.cc = v.cc
			}
		case v := <-rdCh:
			got++
			if best.rir == "" && v.rir != "" {
				best.rir = v.rir
			}
			if best.cc == "" && v.cc != "" {
				best.cc = v.cc
			}
		case <-ctx.Done():
			// return what we have so far
			if best.rir == "" && best.cc == "" {
				return "", "", ctx.Err()
			}
			return best.rir, best.cc, nil
		}
	}

	// If we got a RIR but country is still empty, try RIR-specific RDAP country within the same ctx.
	if best.rir != "" && best.cc == "" {
		baseByRIR := map[string]string{
			"ARIN":     "https://rdap.arin.net/registry/ip",
			"RIPE NCC": "https://rdap.db.ripe.net/ip",
			"APNIC":    "https://rdap.apnic.net/ip",
			"LACNIC":   "https://rdap.lacnic.net/rdap/ip",
			"AFRINIC":  "https://rdap.afrinic.net/rdap/ip",
		}
		if base, ok := baseByRIR[best.rir]; ok {
			if cc, err := rdapCountry(ctx, httpc, base, ip); err == nil && cc != "" {
				best.cc = normalizeCountryCode(cc)
			}
		}
	}

	if best.rir == "" && best.cc == "" {
		return "", "", errors.New("empty registry result")
	}
	return best.rir, best.cc, nil
}

// needsFallback returns true if we still miss key display fields.
// Some providers may return success=true but omit fields for certain targets.
// In that case we continue querying fallback sources to fill blanks.
// needsBasicFallback returns true if we still miss key *basic* display fields.
// It is used to decide whether to query additional fast geo/ASN/org sources.
// It intentionally does NOT include registry/reg_region because those are not provided
// by the basic fallback providers and are handled by a dedicated registry lookup.
func needsBasicFallback(info IPInfo) bool {
	if strings.TrimSpace(info.Country) == "" && strings.TrimSpace(info.CountryCode) == "" {
		return true
	}
	if strings.TrimSpace(info.ASN) == "" {
		return true
	}
	if strings.TrimSpace(info.ASNOwner) == "" {
		return true
	}
	if strings.TrimSpace(info.Org) == "" {
		return true
	}
	// City is nice-to-have, but we still treat it as a fallback trigger
	// because the UI shows “地理位置”。
	if strings.TrimSpace(info.City) == "" {
		return true
	}
	return false
}

// needsFallback returns true if we still miss key display fields for the *first paint*.
// Compared to needsBasicFallback, this also treats registry/reg_region as required.
// This aligns with the frontend expectation that “注册局/地区” is a peer of ASN/Org fields.
func needsFallback(info IPInfo) bool {
	if needsBasicFallback(info) {
		return true
	}
	if strings.TrimSpace(info.Registry) == "" {
		return true
	}
	if strings.TrimSpace(info.RegRegion) == "" {
		return true
	}
	return false
}

// scoreResourceSpecificity prefers more specific allocations.
// Higher score = more specific.
func scoreResourceSpecificity(resource string) int {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return 0
	}
	if strings.Contains(resource, "/") {
		// prefix length
		parts := strings.Split(resource, "/")
		if len(parts) == 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				return 1000 + n
			}
		}
	}
	// range "a - b" or "a-b"
	resource = strings.ReplaceAll(resource, " ", "")
	if strings.Contains(resource, "-") {
		parts := strings.Split(resource, "-")
		if len(parts) == 2 {
			ip1 := net.ParseIP(parts[0])
			ip2 := net.ParseIP(parts[1])
			if ip1 != nil && ip2 != nil {
				// smaller range = more specific
				return 500
			}
		}
	}
	return 1
}

// ---------------------------
// Data sources (basic): ipwho.is (primary) + ip-api.com/ipapi.org (fallback)
// ---------------------------

func fillFromIPWho(ctx context.Context, c *http.Client, info *IPInfo) error {
	u := fmt.Sprintf("https://ipwho.is/%s", url.PathEscape(info.IP))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	var d struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Flag        struct {
			Img string `json:"img"`
		} `json:"flag"`
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
			// Some ipwho.is responses also provide a representative domain in connection.domain
			Domain string `json:"domain"`
		} `json:"connection"`
		Security map[string]any `json:"security"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return err
	}
	if !d.Success {
		if d.Message != "" {
			return errors.New(d.Message)
		}
		return errors.New("ipwho.is success=false")
	}

	if strings.TrimSpace(d.Country) != "" && strings.TrimSpace(info.Country) == "" {
		info.Country = d.Country
	}
	cc := strings.ToUpper(strings.TrimSpace(d.CountryCode))
	if cc != "" && strings.TrimSpace(info.CountryCode) == "" {
		info.CountryCode = cc
	}
	if strings.TrimSpace(d.City) != "" && strings.TrimSpace(info.City) == "" {
		info.City = d.City
	}
	// 注意：RegRegion 用于“注册国别(ISO2)”展示，不要用 geo API 的国家覆盖。
	// Org/ISP 采用“更长/信息更完整”的值优先（例如 365 Group LLC > Group LLC）。
	candISP := strings.TrimSpace(firstNonEmpty(d.Connection.ISP, d.Connection.Org))
	if candISP != "" && (info.ISP == "" || len(candISP) > len(info.ISP)) {
		info.ISP = candISP
	}

	// Fallback: fill org from ipwho.is connection.org when missing
	if strings.TrimSpace(info.Org) == "" {
		if org := strings.TrimSpace(d.Connection.Org); org != "" {
			info.Org = org
			info.OrgSource = "ipwho.is:connection.org"
			recordFieldSource("org", "ipwho.is:connection.org", info.IP)
		}
	}

	if info.Lat == 0 && d.Latitude != 0 {
		info.Lat = d.Latitude
	}
	if info.Lon == 0 && d.Longitude != 0 {
		info.Lon = d.Longitude
	}

	// Links / domains
	if dom := strings.TrimSpace(d.Connection.Domain); dom != "" {
		// 企业信息链接兜底：ipwho.is connection.domain
		if info.OrgDomain == "" {
			info.OrgDomain = dom
			if info.OrgDomain != "" {
				info.OrgDomainSource = "ipwho.is:connection.domain"
				recordFieldSource("org_domain", "ipwho.is:connection.domain", info.IP)
			}
		}
	}

	// Security/proxy/hosting signals (multi-source merged)
	if d.Security != nil {
		proxy := getBool(d.Security, "proxy") || getBool(d.Security, "is_proxy")
		vpn := getBool(d.Security, "vpn") || getBool(d.Security, "is_vpn")
		tor := getBool(d.Security, "tor") || getBool(d.Security, "is_tor")
		hosting := getBool(d.Security, "hosting") || getBool(d.Security, "is_hosting")
		if proxy {
			noteSignal(info, "proxy", "ipwho.is", true)
			setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ipwho.is")
		}
		if vpn {
			noteSignal(info, "vpn", "ipwho.is", true)
			setTrueSignal(&info.IPAPIVPN, &info.VPNSource, "ipwho.is")
		}
		if tor {
			noteSignal(info, "tor", "ipwho.is", true)
			setTrueSignal(&info.IPAPITOR, &info.TORSource, "ipwho.is")
		}
		if hosting {
			noteSignal(info, "hosting", "ipwho.is", true)
			setTrueSignal(&info.IPAPIHosting, &info.HostingSource, "ipwho.is")
		}
	}

	if looksLikeDatacenter(info.ISP, info.Org, "") {
		info.IPType = "机房/数据中心 (Data Center)"
	} else {
		info.IPType = "住宅/原生 (Residential)"
	}

	if d.Connection.ASN != 0 {
		info.ASN = fmt.Sprintf("AS%d", d.Connection.ASN)
	}
	if strings.TrimSpace(info.ASNOwner) == "" {
		// 用户口径：ASN 所有者优先使用 ipwho.is 的 isp
		info.ASNOwner = strings.TrimSpace(d.Connection.ISP)
		if info.ASNOwner != "" {
			info.ASNOwnerSource = "ipwho.is:connection.isp"
			recordFieldSource("asn_owner", "ipwho.is:connection.isp", info.IP)
		}
	}
	return nil
}

func fillFromIPAPICom(ctx context.Context, c *http.Client, info *IPInfo) error {
	// ip-api.com free endpoint (no key). We'll request only fields we need.
	fields := "status,message,query,country,countryCode,city,lat,lon,isp,org,as,mobile,proxy,hosting"
	u := fmt.Sprintf("http://ip-api.com/json/%s?fields=%s", url.PathEscape(info.IP), url.QueryEscape(fields))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	var d struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Mobile      bool    `json:"mobile"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return err
	}
	if strings.ToLower(d.Status) != "success" {
		if d.Message != "" {
			return errors.New(d.Message)
		}
		return errors.New("ip-api.com status!=success")
	}

	if info.Country == "" {
		info.Country = d.Country
	}
	if info.CountryCode == "" {
		info.CountryCode = strings.ToUpper(strings.TrimSpace(d.CountryCode))
	}
	if info.City == "" {
		info.City = d.City
	}
	if info.Lat == 0 {
		info.Lat = d.Lat
	}
	if info.Lon == 0 {
		info.Lon = d.Lon
	}

	// org/isp: prefer longer/more complete
	candOrg := strings.TrimSpace(firstNonEmpty(d.Org, d.ISP))
	candISP := strings.TrimSpace(firstNonEmpty(d.ISP, d.Org))
	if candOrg != "" && (info.Org == "" || len(candOrg) > len(info.Org)) {
		info.Org = candOrg
	}
	if candISP != "" && (info.ISP == "" || len(candISP) > len(info.ISP)) {
		info.ISP = candISP
	}

	// ASN / ASN owner: ip-api.com provides "as" like "AS15169 Google LLC"

	asn, owner := parseASField(d.AS)
	if info.ASN == "" && asn != "" {
		info.ASN = asn
	}
	if info.ASNOwner == "" && owner != "" {
		info.ASNOwner = owner
	}

	// ip-api.com flags (only set if we don't already have a signal from a higher-priority source)
	noteSignal(info, "hosting", "ip-api.com", d.Hosting)
	noteSignal(info, "proxy", "ip-api.com", d.Proxy)
	setTrueSignal(&info.IPAPIHosting, &info.HostingSource, "ip-api.com", d.Hosting)
	setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ip-api.com", d.Proxy)
	setTrueSignal(&info.IPAPIMobile, &info.MobileSource, "ip-api.com", d.Mobile)

	if looksLikeDatacenter(info.ISP, info.Org, info.ASNOwner) {
		info.IPType = "机房/数据中心 (Data Center)"
	} else if info.IPType == "" {
		info.IPType = "住宅/原生 (Residential)"
	}
	return nil
}

var errNoAPIKey = errors.New("missing API key")

func fillFromIPApiOrg(ctx context.Context, c *http.Client, info *IPInfo) error {
	// ipapi.org (Pro) requires API key. We'll skip if not configured.
	key := strings.TrimSpace(getEnv("IPAPI_ORG_KEY"))
	if key == "" {
		key = defaultIPAPIOrgKey
	}
	if key == "" {
		return errNoAPIKey
	}
	fields := "country,countryCode,city,lat,lon,asn,asname,isp,org,domain"
	u := fmt.Sprintf("https://pro.ipapi.org/api_json/one.php?key=%s&ip=%s&fields=%s", url.PathEscape(info.IP), url.QueryEscape(key), url.QueryEscape(fields))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	// ipapi.org returns a flat JSON; errors may be embedded.
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return err
	}
	if v, ok := d["error"]; ok && v != nil {
		// best-effort error message
		return fmt.Errorf("api error: %v", v)
	}

	if info.Country == "" {
		info.Country = getString(d, "country")
	}
	if info.CountryCode == "" {
		info.CountryCode = strings.ToUpper(strings.TrimSpace(getString(d, "countryCode")))
	}
	if info.City == "" {
		info.City = getString(d, "city")
	}
	if info.Lat == 0 {
		info.Lat = getFloat(d, "lat")
	}
	if info.Lon == 0 {
		info.Lon = getFloat(d, "lon")
	}

	// ASN / ASN owner
	if info.ASN == "" {
		if asn := strings.TrimSpace(getString(d, "asn")); asn != "" {
			info.ASN = "AS" + asn
		}
	}
	if info.ASNOwner == "" {
		info.ASNOwner = strings.TrimSpace(firstNonEmpty(getString(d, "asname"), getString(d, "isp")))
	}

	// Org / ISP / Domain
	candOrg := strings.TrimSpace(firstNonEmpty(getString(d, "org"), getString(d, "isp")))
	candISP := strings.TrimSpace(firstNonEmpty(getString(d, "isp"), getString(d, "org")))
	if candOrg != "" && (info.Org == "" || len(candOrg) > len(info.Org)) {
		info.Org = candOrg
	}
	if candISP != "" && (info.ISP == "" || len(candISP) > len(info.ISP)) {
		info.ISP = candISP
	}
	if dmn := strings.TrimSpace(getString(d, "domain")); dmn != "" {
		if info.OrgDomain == "" {
			info.OrgDomain = dmn
		}
	}

	if looksLikeDatacenter(info.ISP, info.Org, info.ASNOwner) {
		info.IPType = "机房/数据中心 (Data Center)"
	} else if info.IPType == "" {
		info.IPType = "住宅/原生 (Residential)"
	}
	return nil
}

// ---------------------------
// Org/Domain sources: ipinfo.io
// ---------------------------
func fillFromIPInfoIO(ctx context.Context, c *http.Client, info *IPInfo) error {
	// ipinfo.io requires token for higher limits; if missing we skip silently.
	token := getEnvOrDefault("IPINFO_TOKEN", defaultIPInfoToken)
	if token == "" {
		return errNoAPIKey
	}
	u := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", url.PathEscape(info.IP), url.QueryEscape(token))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	var root map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return err
	}
	// We only care about "as_domain" as ASN 所有者域名兜底
	if info.AsnDomain == "" {
		if s := strings.TrimSpace(getString(root, "as_domain")); s != "" {
			info.AsnDomain = s
			info.AsnDomainSource = "ipinfo.io:as_domain"
			recordFieldSource("asn_domain", "ipinfo.io:as_domain", info.IP)
		}
	}
	return nil
}

// ---------------------------
// Org/Domain + Flag sources: ipdata.co
// ---------------------------
func fillFromIPDataCo(ctx context.Context, c *http.Client, info *IPInfo) error {
	key := getEnvOrDefault("IPDATA_KEY", defaultIPDataKey)
	if key == "" {
		return errNoAPIKey
	}
	u := fmt.Sprintf("https://api.ipdata.co/%s?api-key=%s", url.PathEscape(info.IP), url.QueryEscape(key))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	var root map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return err
	}

	// Threat / security signals (ipdata.co). These are useful for IP属性/风险分/人机比。
	// ipdata.co commonly returns them under threat.*; be tolerant to top-level fields too.
	threatObj := getMap(root, "threat")
	getThreatBool := func(k string) bool {
		// Prefer threat.* when present; fall back to top-level.
		if threatObj != nil {
			if _, ok := threatObj[k]; ok {
				return getBool(threatObj, k)
			}
		}
		if _, ok := root[k]; ok {
			return getBool(root, k)
		}
		return false
	}
	// Map ipdata signals into existing internal flags.
	// NOTE: we treat "is_anonymous" and "is_icloud" as proxy/anonymizer signals.
	if getThreatBool("is_tor") {
		setTrueSignal(&info.IPAPITOR, &info.TORSource, "ipdata.co:threat.is_tor", true)
		noteSignal(info, "tor", "ipdata.co:threat.is_tor", true)
	}
	if getThreatBool("is_proxy") {
		setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ipdata.co:threat.is_proxy", true)
		noteSignal(info, "proxy", "ipdata.co:threat.is_proxy", true)
	}
	if getThreatBool("is_anonymous") {
		setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ipdata.co:threat.is_anonymous", true)
		noteSignal(info, "proxy", "ipdata.co:threat.is_anonymous", true)
	}
	if getThreatBool("is_icloud") {
		setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ipdata.co:threat.is_icloud", true)
		noteSignal(info, "proxy", "ipdata.co:threat.is_icloud", true)
	}

	// Security risk hints (ipdata.co): feed into risk score only (NOT IP属性).
	// These are not the same as "datacenter" and are less likely to mislead IP属性 classification.
	if getThreatBool("is_threat") {
		// Record as an internal risk signal (not exposed).
		setTrueSignal(&info.IPAPIThreat, &info.ThreatSource, "ipdata.co:threat.is_threat", true)
		noteSignal(info, "threat", "ipdata.co:threat.is_threat", true)
	}
	// ipdata.co uses "is_known_attacker"/"is_known_abuser" (keep tolerance for misspells too).
	if getThreatBool("is_known_attacker") || getThreatBool("is_know_attacker") {
		setTrueSignal(&info.IPAPIKnownAttacker, &info.KnownAttackerSource, "ipdata.co:threat.is_known_attacker", true)
		noteSignal(info, "known_attacker", "ipdata.co:threat.is_known_attacker", true)
	}
	if getThreatBool("is_known_abuser") || getThreatBool("is_know_abuser") {
		setTrueSignal(&info.IPAPIKnownAbuser, &info.KnownAbuserSource, "ipdata.co:threat.is_known_abuser", true)
		noteSignal(info, "known_abuser", "ipdata.co:threat.is_known_abuser", true)
	}

	// ASN 所有者域名兜底：asn.domain
	if info.AsnDomain == "" {
		asnObj := getMap(root, "asn")
		if d := strings.TrimSpace(getString(asnObj, "domain")); d != "" {
			info.AsnDomain = d
			info.AsnDomainSource = "ipdata.co:asn.domain"
			recordFieldSource("asn_domain", "ipdata.co:asn.domain", info.IP)
		}
	}

	return nil
}

func fillFromIPApiIs(ctx context.Context, c *http.Client, info *IPInfo) error {
	// ipapi.is supports free plan without a key, but you can pass key to raise limits.
	// Docs: https://ipapi.is/developers.html  (GET https://api.ipapi.is?q=<ip>&key=<key>)
	key := strings.TrimSpace(getEnv("IPAPI_IS_KEY"))
	if key == "" {
		key = defaultIPAPIIsKey
	}
	uu, _ := url.Parse("https://api.ipapi.is")
	q := uu.Query()
	q.Set("q", info.IP)
	if key != "" {
		q.Set("key", key)
	}
	uu.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uu.String(), nil)
	req.Header.Set("User-Agent", "PurePure/1.0")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		// Retry once on transient connection resets (common with some networks / HTTP2)
		if strings.Contains(err.Error(), "forcibly closed") || strings.Contains(err.Error(), "connection reset") {
			tc := &http.Client{Timeout: PerCallTimeout, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: false, DisableKeepAlives: true, TLSHandshakeTimeout: 6 * time.Second, ResponseHeaderTimeout: 7 * time.Second}}
			resp, err = tc.Do(req)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	// ipapi.is returns HTTP 200 even on error, with an "error" field.
	var root map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return err
	}
	if e := strings.TrimSpace(getString(root, "error")); e != "" {
		return errors.New(e)
	}

	// location
	if info.Country == "" {
		// Some responses may use nested location/country (name), be tolerant.
		info.Country = strings.TrimSpace(firstNonEmpty(
			getString(getMap(root, "location"), "country"),
			getString(root, "country"),
		))
	}
	if info.CountryCode == "" {
		cc := strings.TrimSpace(firstNonEmpty(
			getString(getMap(getMap(root, "location"), "country"), "code"),
			getString(getMap(root, "location"), "country_code"),
			getString(root, "country_code"),
		))
		info.CountryCode = strings.ToUpper(cc)
		// Flag image: ipapi.is does not provide a direct flag URL, derive it from country_code (low-risk).

	}
	if info.City == "" {
		info.City = strings.TrimSpace(firstNonEmpty(
			getString(getMap(root, "location"), "city"),
			getString(root, "city"),
		))
	}
	if info.Lat == 0 {
		info.Lat = getFloat(getMap(root, "location"), "latitude")
		if info.Lat == 0 {
			info.Lat = getFloat(root, "lat")
		}
	}
	if info.Lon == 0 {
		info.Lon = getFloat(getMap(root, "location"), "longitude")
		if info.Lon == 0 {
			info.Lon = getFloat(root, "lon")
		}
	}

	// ASN block
	asnObj := getMap(root, "asn")
	// Prefer ipapi.is for registry + asn country (fast single-call).
	// registry: use top-level "rir" field.
	if strings.TrimSpace(info.Registry) == "" || strings.TrimSpace(info.Registry) == "Global Registry" {
		if rir := strings.TrimSpace(firstNonEmpty(getString(root, "rir"), getString(getMap(root, "registry"), "rir"))); rir != "" {
			info.Registry = normalizeRIRName(rir)
		}
	}
	// reg_region: use asn.country (2-letter code like CN/US/CA)
	if strings.TrimSpace(info.RegRegion) == "" {
		if cc := strings.TrimSpace(getString(asnObj, "country")); cc != "" {
			info.RegRegion = normalizeCountryCode(cc)
		}
	}

	// asn_domain: use asn.domain (ASN owner domain)
	if strings.TrimSpace(info.AsnDomain) == "" {
		if d := strings.TrimSpace(getString(asnObj, "domain")); d != "" {
			info.AsnDomain = d
			info.AsnDomainSource = "ipapi.is:asn.domain"
			recordFieldSource("asn_domain", "ipapi.is:asn.domain", info.IP)
		}
	}
	if info.IPAPIIsASNType == "" {
		if t := strings.TrimSpace(getString(asnObj, "type")); t != "" {
			info.IPAPIIsASNType = t
		}
	}
	// "ASN 号码" => asn.asn
	if info.ASN == "" {
		if n := getInt(asnObj, "asn"); n > 0 {
			info.ASN = fmt.Sprintf("AS%d", n)
		} else if s := strings.TrimSpace(getString(asnObj, "asn")); s != "" {
			info.ASN = "AS" + strings.TrimPrefix(s, "AS")
		}
	}
	// "ASN 所有者" => asn.org
	if info.ASNOwner == "" {
		info.ASNOwner = strings.TrimSpace(getString(asnObj, "org"))
		if info.ASNOwner != "" {
			info.ASNOwnerSource = "ipapi.is:asn.org"
			recordFieldSource("asn_owner", "ipapi.is:asn.org", info.IP)
		}
	}
	// ASN domain: used for "ASN 所有者" link
	if d := strings.TrimSpace(getString(asnObj, "domain")); d != "" {
		if info.AsnDomain == "" {
			info.AsnDomain = d
			info.AsnDomainSource = "ipapi.is:asn.domain"
			recordFieldSource("asn_domain", "ipapi.is:asn.domain", info.IP)
		}
	}

	// Company block
	compObj := getMap(root, "company")
	if info.IPAPIIsCompanyType == "" {
		if t := strings.TrimSpace(getString(compObj, "type")); t != "" {
			info.IPAPIIsCompanyType = t
		}
	}
	// "企业信息" => company.name
	candOrg := strings.TrimSpace(getString(compObj, "name"))
	if candOrg != "" && (info.Org == "" || len(candOrg) > len(info.Org)) {
		info.Org = candOrg
		info.OrgSource = "ipapi.is:company.name"
		recordFieldSource("org", "ipapi.is:company.name", info.IP)
	}
	// Company domain: used for "企业信息" link
	if d := strings.TrimSpace(getString(compObj, "domain")); d != "" {
		if info.OrgDomain == "" {
			info.OrgDomain = d
			info.OrgDomainSource = "ipapi.is:company.domain"
			recordFieldSource("org_domain", "ipapi.is:company.domain", info.IP)
		}
	}

	// ISP fallback (some ipapi.is responses include "company" but also "isp" or similar)
	if info.ISP == "" {
		info.ISP = strings.TrimSpace(firstNonEmpty(getString(root, "isp"), getString(compObj, "name"), getString(asnObj, "org")))
	}

	// Security/proxy/hosting signals (multi-source merged)
	sec := getMap(root, "security")
	privacy := getMap(root, "privacy")
	proxy := getBool(root, "is_proxy") || getBool(root, "proxy") || getBool(sec, "is_proxy") || getBool(sec, "proxy") || getBool(privacy, "is_proxy") || getBool(privacy, "proxy")
	vpn := getBool(root, "is_vpn") || getBool(root, "vpn") || getBool(sec, "is_vpn") || getBool(sec, "vpn") || getBool(privacy, "is_vpn") || getBool(privacy, "vpn")
	tor := getBool(root, "is_tor") || getBool(root, "tor") || getBool(sec, "is_tor") || getBool(sec, "tor") || getBool(privacy, "is_tor") || getBool(privacy, "tor")
	hosting := getBool(root, "is_hosting") || getBool(root, "hosting") || getBool(sec, "is_hosting") || getBool(sec, "hosting") || getBool(privacy, "is_hosting") || getBool(privacy, "hosting")
	if proxy {
		noteSignal(info, "proxy", "ipapi.is", true)
		setTrueSignal(&info.IPAPIProxy, &info.ProxySource, "ipapi.is")
	}
	if vpn {
		noteSignal(info, "vpn", "ipapi.is", true)
		setTrueSignal(&info.IPAPIVPN, &info.VPNSource, "ipapi.is")
	}
	if tor {
		noteSignal(info, "tor", "ipapi.is", true)
		setTrueSignal(&info.IPAPITOR, &info.TORSource, "ipapi.is")
	}
	if hosting {
		noteSignal(info, "hosting", "ipapi.is", true)
		setTrueSignal(&info.IPAPIHosting, &info.HostingSource, "ipapi.is")
	}
	// also infer hosting from ipapi.is type
	if strings.Contains(strings.ToLower(firstNonEmpty(info.IPAPIIsCompanyType, info.IPAPIIsASNType)), "host") || strings.Contains(strings.ToLower(firstNonEmpty(info.IPAPIIsCompanyType, info.IPAPIIsASNType)), "data") {
		noteSignal(info, "hosting", "ipapi.is", true)
		setTrueSignal(&info.IPAPIHosting, &info.HostingSource, "ipapi.is")
	}

	if looksLikeDatacenter(info.ISP, info.Org, info.ASNOwner) {
		info.IPType = "机房/数据中心 (Data Center)"
	} else if info.IPType == "" {
		info.IPType = "住宅/原生 (Residential)"
	}
	return nil
}

// ---------------------------
// ✅ BGP Topology (RIPEstat) — Upstreams ONLY (1-hop)
// ---------------------------
//
// 目标：稳定、快速、永不因为“找不到 Tier-1 路径”而报错。
// - 只使用 RIPEstat 的 asn-neighbours
// - 只看 neighbours.left（按 RIPEstat 统计推断的上游方向）
// - 只展示 1-hop upstreams：AS(origin) -> AS(upstream)
// - 不再做 Tier-1 路径搜索/递归扩展
//
// 注意：RIPEstat 的 left/right 来自 AS-PATH 统计推断，并非严格商业关系；这里仅作为“上游方向”的近似。

// Tier-1 ASN set (used only for coloring/grouping in UI via is_tier1).
// You can adjust this list as you like.
var tier1ASNSet = map[int]struct{}{
	174:  {}, // Cogent
	3356: {}, // Lumen/Level3
	2914: {}, // NTT
	3257: {}, // GTT
	6762: {}, // Telecom Italia Sparkle
	1299: {}, // Arelion (Telia)
	6453: {}, // Tata Communications
	7018: {}, // AT&T
	3491: {}, // PCCW
	3320: {}, // Deutsche Telekom
	1239: {}, // Sprint (legacy, often still referenced)
	5511: {}, // Orange
}

func isTier1ASN(asn int) bool {
	_, ok := tier1ASNSet[asn]
	return ok
}

type ripeUpItem struct {
	ASN       int
	Power     int
	Uncertain bool
}

// ---------------------------
// ASN name lookup (RIPEstat as-overview) with small TTL cache
// ---------------------------

func ripeASName(ctx context.Context, c *http.Client, asn int) string {
	if asn <= 0 {
		return ""
	}

	if v, ok, negative := asNameCacheGet(asn); ok {
		return v
	} else if negative {
		return ""
	}

	// keep this lookup cheap; do not let it delay topology too much
	ctx2, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	u := fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%d", asn)
	req, _ := http.NewRequestWithContext(ctx2, "GET", u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "myip-bgp/18 (+https://stat.ripe.net)")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.Do(req)
	if err != nil {
		asNameCacheNeg(asn, 30*time.Minute)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		asNameCacheNeg(asn, 30*time.Minute)
		return ""
	}

	body := resp.Body
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr == nil {
			defer gz.Close()
			body = gz
		}
	}

	var root map[string]any
	if err := json.NewDecoder(body).Decode(&root); err != nil {
		asNameCacheNeg(asn, 30*time.Minute)
		return ""
	}

	data, _ := root["data"].(map[string]any)
	getStr := func(m map[string]any, key string) string {
		if m == nil {
			return ""
		}
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
		return ""
	}

	name := firstNonEmpty(
		getStr(data, "holder"),
		getStr(data, "name"),
		getStr(data, "as_name"),
		getStr(data, "as-name"),
		getStr(data, "org_name"),
	)
	name = strings.TrimSpace(name)

	if name == "" {
		asNameCacheNeg(asn, 6*time.Hour)
		return ""
	}

	asNameCacheSet(asn, name, 24*time.Hour)
	return name
}

// ripeASNUpstreamsCap stream-parses RIPEstat asn-neighbours and returns ONLY neighbours.left.
// It supports both output shapes:
//   A) data.neighbours = [ {asn/neighbour, type/position, power, uncertain}, ... ]
//   B) data.neighbours = { left:[...], right:[...], uncertain:[...] }

func ripeASNUpstreamsCap(ctx context.Context, c *http.Client, asn int, capN int) ([]ripeUpItem, error) {
	if capN <= 0 {
		capN = 24
	}

	url := fmt.Sprintf("https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS%d", asn)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "myip-bgp/18 (+https://stat.ripe.net)")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ripestat(asn-neighbours): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := ""
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if len(b) > 0 {
			snippet = strings.TrimSpace(string(b))
			snippet = strings.ReplaceAll(snippet, "\n", " ")
			if len(snippet) > 180 {
				snippet = snippet[:180] + "…"
			}
		}
		if snippet != "" {
			return nil, fmt.Errorf("ripestat(asn-neighbours): http %d: %s", resp.StatusCode, snippet)
		}
		return nil, fmt.Errorf("ripestat(asn-neighbours): http %d", resp.StatusCode)
	}

	body := resp.Body
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr == nil {
			defer gz.Close()
			body = gz
		}
	}

	// NOTE: We intentionally decode a small wrapper first and then decode only the neighbours payload.
	// This avoids brittle streaming token heuristics and works across minor API shape variations.
	type neighItem struct {
		ASN       int    `json:"asn"`
		Neighbour int    `json:"neighbour"`
		Type      string `json:"type"`
		Position  string `json:"position"`
		Power     int    `json:"power"`
		Uncertain bool   `json:"uncertain"`
	}
	type wrap struct {
		Data struct {
			Neighbours json.RawMessage `json:"neighbours"`
		} `json:"data"`
	}

	var w wrap
	if err := json.NewDecoder(body).Decode(&w); err != nil {
		return nil, fmt.Errorf("ripestat(asn-neighbours): %w", err)
	}
	raw := bytes.TrimSpace(w.Data.Neighbours)
	if len(raw) == 0 {
		return nil, errors.New("ripestat(asn-neighbours): empty neighbours")
	}

	items := make([]neighItem, 0, capN*4)

	switch raw[0] {
	case '[':
		// Shape A: neighbours is an array of items with type/position markers.
		var all []neighItem
		if err := json.Unmarshal(raw, &all); err != nil {
			return nil, fmt.Errorf("ripestat(asn-neighbours): %w", err)
		}
		for _, it := range all {
			typ := strings.ToLower(strings.TrimSpace(it.Type))
			if typ == "" {
				typ = strings.ToLower(strings.TrimSpace(it.Position))
			}
			if typ == "left" {
				items = append(items, it)
			}
		}
	case '{':
		// Shape B: neighbours is an object like {"left":[...], "right":[...], ...}
		var buckets map[string]json.RawMessage
		if err := json.Unmarshal(raw, &buckets); err != nil {
			return nil, fmt.Errorf("ripestat(asn-neighbours): %w", err)
		}
		var left []neighItem
		if b, ok := buckets["left"]; ok && len(bytes.TrimSpace(b)) > 0 {
			_ = json.Unmarshal(b, &left)
		} else if b, ok := buckets["Left"]; ok && len(bytes.TrimSpace(b)) > 0 {
			_ = json.Unmarshal(b, &left)
		}
		items = append(items, left...)
	default:
		return nil, errors.New("ripestat(asn-neighbours): unexpected neighbours json shape")
	}

	seen := map[int]struct{}{}
	out := make([]ripeUpItem, 0, capN)

	for _, it := range items {
		asn2 := it.ASN
		if asn2 <= 0 {
			asn2 = it.Neighbour
		}
		if asn2 <= 0 || asn2 == asn {
			continue
		}
		if _, ok := seen[asn2]; ok {
			continue
		}
		seen[asn2] = struct{}{}
		out = append(out, ripeUpItem{ASN: asn2, Power: it.Power, Uncertain: it.Uncertain})
	}

	// Prefer higher power; deterministic tie-breaker by ASN.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Power != out[j].Power {
			return out[i].Power > out[j].Power
		}
		return out[i].ASN < out[j].ASN
	})
	if len(out) > capN {
		out = out[:capN]
	}

	return out, nil
}

// ripeASNUpstreamsWithRetryCap retries once on errors/empty (RIPEstat can occasionally return empty).
func ripeASNUpstreamsWithRetryCap(ctx context.Context, c *http.Client, asn int, capN int) ([]ripeUpItem, error) {
	u, err := ripeASNUpstreamsCap(ctx, c, asn, capN)
	if err == nil && len(u) > 0 {
		return u, nil
	}
	select {
	case <-time.After(120 * time.Millisecond):
	case <-ctx.Done():
		if err != nil {
			return nil, err
		}
		return u, ctx.Err()
	}
	u2, err2 := ripeASNUpstreamsCap(ctx, c, asn, capN)
	if err2 == nil && len(u2) > 0 {
		return u2, nil
	}
	if err2 == nil && err == nil {
		return u2, errors.New("ripestat(asn-neighbours): empty")
	}
	if err2 != nil {
		return nil, err2
	}
	return u2, err
}

// fetchBGPTopologyCap builds a topology payload that contains ONLY 1-hop upstream neighbours.
// It keeps the response schema stable for the existing frontend.
func fetchBGPTopologyCap(ctx context.Context, c *http.Client, asn int, perNodeCap int) (*BGPTopology, error) {
	// Upstreams-only, 1-hop topology (no Tier-1 path search).
	topo := minimalBGPTopology(asn)
	if topo == nil {
		return nil, errors.New("invalid asn")
	}

	ups, err := ripeASNUpstreamsWithRetryCap(ctx, c, asn, perNodeCap)
	if err != nil {
		return nil, err
	}

	// Fill ASN names (best-effort; should never block topology rendering)
	topo.Name = ripeASName(ctx, c, asn)

	// Lookup upstream names with a small overall budget.
	ctxNames, cancelNames := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancelNames()

	nameMap := make(map[int]string, len(ups))
	var nameMu sync.Mutex
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, u := range ups {
		uASN := u.ASN
		if uASN <= 0 || uASN == asn {
			continue
		}
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			nm := ripeASName(ctxNames, c, a)
			nameMu.Lock()
			nameMap[a] = nm
			nameMu.Unlock()
		}(uASN)
	}
	wg.Wait()

	// Build upstream list
	topo.Upstreams = make([]ASNNode, 0, len(ups))
	for _, u := range ups {
		topo.Upstreams = append(topo.Upstreams, ASNNode{ASN: u.ASN, Name: nameMap[u.ASN], IsTier1: isTier1ASN(u.ASN)})
	}

	topo.Source = "RIPEstat"
	return topo, nil
}

// ---------------------------
// Risk & classification（保持你原逻辑）
// ---------------------------

func computeRiskScore(info IPInfo, asnCC string, cidr string) int {
	score := 0

	if looksLikeDatacenter(info.ISP, info.Org, info.ASNOwner) || strings.Contains(info.IPType, "Data Center") {
		score += 45
	} else {
		score += 10
	}

	if isKnownCloudOrIDC(info.ISP, info.Org, info.ASNOwner) {
		score += 20
	}

	score += asnReputationDelta(info.ISP, info.Org, info.ASNOwner)

	cc1 := strings.ToUpper(strings.TrimSpace(info.RegRegion))
	cc2 := strings.ToUpper(strings.TrimSpace(asnCC))
	if cc1 != "" && cc2 != "" && cc1 != cc2 {
		score += 8
	}

	if clusterStrengthHigh(info.ISP, info.Org, info.ASNOwner) {
		score += 12
	}

	if cidr != "" && strings.Contains(cidr, "/") {
		mask := strings.Split(cidr, "/")[1]
		if mask == "24" || mask == "23" || mask == "22" {
			score += 5
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func looksLikeDatacenter(isp, org, asnOwner string) bool {
	s := strings.ToLower(strings.Join([]string{isp, org, asnOwner}, " "))
	keywords := []string{"datacenter", "data center", "hosting", "vps", "colo", "colocation", "server", "cloud", "ovh", "hetzner", "digitalocean", "linode", "vultr", "xtom", "host", "hosting", "colo", "colocation", "server", "vps", "dedicated", "data center", "datacenter", "cloud", "cdn", "transit", "backbone", "isp", "internet", "networks"}
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func isKnownCloudOrIDC(isp, org, asnOwner string) bool {
	s := strings.ToLower(strings.Join([]string{isp, org, asnOwner}, " "))
	known := []string{"amazon", "aws", "google", "gcp", "microsoft", "azure", "cloudflare", "digitalocean", "ovh", "hetzner", "linode", "vultr", "oracle", "tencent", "alibaba"}
	for _, k := range known {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func asnReputationDelta(isp, org, asnOwner string) int {
	s := strings.ToLower(strings.Join([]string{isp, org, asnOwner}, " "))
	bad := []string{"proxy", "vpn", "tor", "bot", "scrape", "crawler", "abuse"}
	good := []string{"telecom", "unicom", "mobile", "verizon", "comcast", "att", "vodafone", "telefonica"}
	for _, k := range bad {
		if strings.Contains(s, k) {
			return 18
		}
	}
	for _, k := range good {
		if strings.Contains(s, k) {
			return -8
		}
	}
	return 0
}

func clusterStrengthHigh(isp, org, asnOwner string) bool {
	return isKnownCloudOrIDC(isp, org, asnOwner) || looksLikeDatacenter(isp, org, asnOwner)
}

// calcIPSourceDetailed returns ip_source plus a short reason string.
func calcIPSourceDetailed(info IPInfo) (string, string) {
	// Strict rule: only compare registration country vs geo country.
	// If both exist and differ => 广播IP, else 原生IP.
	reg := strings.ToUpper(strings.TrimSpace(info.RegRegion))
	geo := strings.ToUpper(strings.TrimSpace(info.CountryCode))
	if reg != "" && geo != "" && reg != geo {
		return "广播IP", fmt.Sprintf("reg!=geo(%s!=%s)", reg, geo)
	}
	return "原生IP", "reg==geo_or_missing"
}

// calcIPPropertyDetailed uses “多源字段优先 + 打分兜底” and returns (property, score map, reasons).
func calcIPPropertyDetailed(info IPInfo) (string, map[string]int, string) {
	// Classify: 家庭IP / 商业IP / 机房IP
	// Use multiple provider fields when available; keep heuristics weak as a last resort.
	scores := map[string]int{"机房IP": 0, "家庭IP": 0, "商业IP": 0}
	reasons := []string{}

	add := func(bucket string, v int, why string) {
		if v == 0 {
			return
		}
		scores[bucket] += v
		if why != "" {
			reasons = append(reasons, why)
		}
	}
	has := func(b *bool) bool { return b != nil && *b }

	// 1) Strong signals: datacenter/hosting/proxy/vpn/tor => DC leaning
	// NOTE: keep weights strong but avoid one bit dominating everything.
	if has(info.IPAPIHosting) {
		add("机房IP", 75, "hosting(+75机房)")
	}
	if has(info.IPAPIProxy) {
		add("机房IP", 35, "proxy(+35机房)")
	}
	if has(info.IPAPIVPN) {
		add("机房IP", 35, "vpn(+35机房)")
	}
	if has(info.IPAPITOR) {
		add("机房IP", 60, "tor(+60机房)")
	}

	// 2) Mobile is a strong consumer signal when no strong DC evidence.
	if has(info.IPAPIMobile) {
		if scores["机房IP"] >= 70 { // already strong DC
			add("家庭IP", 10, "mobile(+10家庭,dc已命中)")
		} else {
			add("家庭IP", 60, "mobile(+60家庭)")
		}
	}

	// 3) Geo-mismatch derived IPSource: weak hint only
	if info.IPSource == "广播IP" {
		add("机房IP", 10, "ip_source=广播IP(+10机房)")
	}

	// 4) ipapi.is / ipdata type fields (moderate)
	// Note: we may get two "type" values (company.type and asn.type). That is intentional,
	// but we de-duplicate identical values and ignore empty/unknown placeholders to avoid double-counting.
	rawTypes := []struct {
		label string
		val   string
	}{
		{label: "company", val: info.IPAPIIsCompanyType},
		{label: "asn", val: info.IPAPIIsASNType},
	}
	seenType := map[string]bool{}
	for _, rt := range rawTypes {
		t := strings.ToLower(strings.TrimSpace(rt.val))
		// Defensive: some providers may return placeholder strings like \""\", "unknown", "n/a"
		t = strings.Trim(t, `"'`)
		if t == "" || t == "unknown" || t == "n/a" || t == "na" {
			continue
		}
		if seenType[t] {
			continue
		}
		seenType[t] = true
		switch {
		case strings.Contains(t, "hosting") || strings.Contains(t, "datacenter") || strings.Contains(t, "data center") || strings.Contains(t, "cloud"):
			add("机房IP", 35, "ipapi.is:type("+rt.label+")="+t+"(+35机房)")
		case strings.Contains(t, "business") || strings.Contains(t, "enterprise"):
			add("商业IP", 20, "ipapi.is:type("+rt.label+")="+t+"(+20商业)")
		case strings.Contains(t, "isp"):
			// "ISP" is not datacenter; treat as residential/business leaning signal when DC evidence is not strong.
			if scores["机房IP"] < 60 {
				add("家庭IP", 15, "type=ISP(+15家庭)")
				add("商业IP", 6, "type=ISP(+6商业)")
			} else {
				add("商业IP", 4, "type=ISP(+4商业,dc已命中)")
			}
		case strings.Contains(t, "residential") || strings.Contains(t, "consumer") || strings.Contains(t, "home"):
			add("家庭IP", 20, "ipapi.is:type("+rt.label+")="+t+"(+20家庭)")
		}
	}

	// 5) Heuristics// 5) Heuristics (weak): keywords & org suffix
	if looksLikeDatacenter(info.ISP, info.Org, info.ASNOwner) {
		// Weak heuristic only; avoid misleading "datacenter" influence without explicit signals.
		if scores["机房IP"] < 40 { // no strong DC evidence
			add("机房IP", 4, "关键词推断(+4机房)")
		}
	}
	// If it looks like a consumer ISP (and we don't have strong DC evidence), lean residential a bit.
	ispBlob := strings.ToLower(strings.Join([]string{info.ISP, info.ASNOwner, info.Org}, " "))
	if scores["机房IP"] < 60 && containsAny(ispBlob, []string{"telecom", "communications", "broadband", "cable", "dsl", "fiber", "mobile", "lte", "5g", "isp"}) {
		add("家庭IP", 12, "isp关键词(+12家庭)")
	}
	orgLower := strings.ToLower(info.Org)
	if strings.Contains(orgLower, "llc") || strings.Contains(orgLower, "ltd") || strings.Contains(orgLower, "inc") || strings.Contains(orgLower, "company") || strings.Contains(orgLower, "corp") {
		add("商业IP", 6, "org后缀公司(+6商业)")
	}

	// 6) Fallback: keep it minimal (do NOT rely on IPType text; it is too noisy).
	if scores["机房IP"] == 0 && scores["家庭IP"] == 0 && scores["商业IP"] == 0 {
		add("家庭IP", 3, "默认兜底(+3家庭)")
	}

	// Pick best; tie-break: 机房 > 商业 > 家庭 (more conservative)
	best := "家庭IP"
	if scores["商业IP"] > scores[best] {
		best = "商业IP"
	}
	if scores["机房IP"] > scores[best] || (scores["机房IP"] == scores[best] && best != "机房IP") {
		best = "机房IP"
	}

	return best, scores, strings.Join(reasons, "; ")
}

// containsAny reports whether s contains any of the provided substrings.
// It is intentionally small and allocation-free.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub == "" {
			continue
		}
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// computeHumanBotDetailed derives bot/% (0-100) from multiple signals and returns a breakdown/reason.
func computeHumanBotDetailed(info IPInfo) (human float64, bot float64, breakdown map[string]int, reason string) {
	breakdown = map[string]int{}
	reasons := []string{}
	botScore := 10
	breakdown["base"] = 10

	add := func(k string, v int, why string) {
		if v == 0 {
			return
		}
		botScore += v
		breakdown[k] = v
		if why != "" {
			reasons = append(reasons, why)
		}
	}

	// Multi-source explicit signals (reuse the same evidence aggregation used by risk score).
	maxWeightSum := 0
	if info.signalTrueWeight != nil {
		for _, w := range info.signalTrueWeight {
			if w > 0 {
				maxWeightSum += w
			}
		}
	}
	if maxWeightSum <= 0 {
		maxWeightSum = 1
	}

	getSig := func(label string) (int, []string) {
		w := 0
		if info.signalTrueWeight != nil {
			w = info.signalTrueWeight[label]
		}
		srcs := []string{}
		if info.signalTrueSources != nil {
			if set, ok := info.signalTrueSources[label]; ok {
				for k := range set {
					srcs = append(srcs, k)
				}
			}
		}
		sort.Strings(srcs)
		return w, srcs
	}

	addWeighted := func(label string, base int, key string) {
		w, srcs := getSig(label)
		if w <= 0 {
			return
		}
		// One strong source is already high confidence.
		frac := 0.6 + 0.4*math.Min(1.0, float64(w)/float64(maxWeightSum))
		adj := int(math.Round(float64(base) * frac))
		if adj == 0 {
			return
		}
		srcText := "unknown"
		if len(srcs) > 0 {
			srcText = strings.Join(srcs, ",")
		}
		add(key, adj, fmt.Sprintf("%s(+%d,w=%d,%s)", label, adj, w, srcText))
	}

	// Bases tuned for stability: tor/proxy are stronger, vpn/hosting moderate.
	addWeighted("tor", 45, "tor")
	addWeighted("proxy", 30, "proxy")
	addWeighted("vpn", 22, "vpn")
	addWeighted("hosting", 18, "hosting")

	// Fallback to ipapi.is booleans only when multi-source evidence is absent for that label.
	if info.IPAPIProxy != nil && *info.IPAPIProxy {
		if w, _ := getSig("proxy"); w <= 0 {
			add("proxy_ipapi", 25, "ipapi_proxy(+25)")
		}
	}
	if info.IPAPIHosting != nil && *info.IPAPIHosting {
		if w, _ := getSig("hosting"); w <= 0 {
			add("hosting_ipapi", 16, "ipapi_hosting(+16)")
		}
	}

	// Mobile is a weak "human leaning" signal; reduce the weight and make it conditional.
	if info.IPAPIMobile != nil && *info.IPAPIMobile {
		wsum := 0
		if w, _ := getSig("tor"); w > 0 {
			wsum += w
		}
		if w, _ := getSig("vpn"); w > 0 {
			wsum += w
		}
		if w, _ := getSig("proxy"); w > 0 {
			wsum += w
		}
		if w, _ := getSig("hosting"); w > 0 {
			wsum += w
		}
		if wsum == 0 {
			add("mobile", -12, "mobile(-12,no_strong_risk)")
		} else {
			add("mobile", -6, "mobile(-6)")
		}
	}

	// Derived signals
	if info.IPSource == "广播IP" {
		add("broadcast", 15, "broadcast(+15)")
	}
	switch info.IPProperty {
	case "机房IP":
		add("datacenter", 10, "datacenter(+10)")
	case "商业IP":
		add("business", 7, "business(+7)")
	case "家庭IP":
		add("residential", -8, "residential(-8)")
	}

	// Keyword heuristics (weak). Keep them small to avoid overfitting.
	blob := strings.ToLower(strings.Join([]string{
		info.Org, info.ASNOwner, info.ISP, info.OrgDomain, info.AsnDomain,
		info.IPAPIIsCompanyType, info.IPAPIIsASNType,
	}, " "))

	if containsAny(blob, []string{"cdn", "cloud", "hosting", "vps", "server", "anycast", "colo", "colocation", "datacenter"}) {
		add("keywords_dc", 8, "keywords_dc(+8)")
	}
	if containsAny(blob, []string{"isp", "broadband", "residential", "fiber", "mobile", "lte", "5g"}) {
		add("keywords_res", -4, "keywords_res(-4)")
	}

	// Clamp and convert to ratio.
	if botScore < 0 {
		botScore = 0
	}
	if botScore > 100 {
		botScore = 100
	}
	bot = float64(botScore)
	human = 100.0 - bot

	reason = strings.Join(reasons, "; ")
	return
}

// computeRiskScoreDetailed is computeRiskScore plus a breakdown/reason string for front-end display.

func computeRiskScoreDetailed(info IPInfo, asnCountry, prefixCountry string) (int, map[string]int, string) {
	breakdown := map[string]int{}
	reasons := []string{}

	// Baseline: unknown is slightly risky (10)
	score := 10
	breakdown["base"] = 10

	// If the target itself is non-public, do not treat as risky.
	if !isPublicIP(net.ParseIP(info.IP)) {
		score = 0
		breakdown["non_public"] = 0
		reasons = append(reasons, "non_public_ip")
		return score, breakdown, strings.Join(reasons, "; ")
	}

	// Multi-source weighted explicit signals (proxy/vpn/tor/hosting)
	maxWeightSum := 0
	for _, w := range providerWeight {
		if w > 0 {
			maxWeightSum += w
		}
	}
	if maxWeightSum <= 0 {
		maxWeightSum = 10
	}

	getSig := func(label string) (int, []string) {
		w := 0
		if info.signalTrueWeight != nil {
			w = info.signalTrueWeight[label]
		}
		srcs := []string{}
		if info.signalTrueSources != nil {
			if set, ok := info.signalTrueSources[label]; ok {
				for k := range set {
					srcs = append(srcs, k)
				}
			}
		}
		sort.Strings(srcs)
		return w, srcs
	}

	addWeighted := func(label string, base int, key string) {
		w, srcs := getSig(label)
		if w <= 0 {
			return
		}
		// One strong source is already high confidence.
		frac := 0.6 + 0.4*math.Min(1.0, float64(w)/float64(maxWeightSum))
		add := int(math.Round(float64(base) * frac))
		if add <= 0 {
			return
		}
		score += add
		breakdown[key] = add
		srcText := "unknown"
		if len(srcs) > 0 {
			srcText = strings.Join(srcs, ",")
		}
		reasons = append(reasons, fmt.Sprintf("%s(+%d,w=%d,%s)", label, add, w, srcText))
	}

	// These bases are intentionally moderate; the final score is capped to 100.
	addWeighted("tor", 30, "tor")
	addWeighted("vpn", 16, "vpn")
	addWeighted("proxy", 20, "proxy")
	addWeighted("hosting", 14, "hosting")
	addWeighted("threat", 18, "threat")
	addWeighted("known_attacker", 26, "known_attacker")
	addWeighted("known_abuser", 20, "known_abuser")

	// Property/source-derived risk boosts (already computed from multi-source signals)
	if info.IPSource == "广播IP" {
		score += 10
		breakdown["broadcast"] = 10
		reasons = append(reasons, "广播IP(+10)")
	}
	if info.IPProperty == "机房IP" {
		score += 10
		breakdown["datacenter"] = 10
		reasons = append(reasons, "机房IP(+10)")
	}

	// Text-based heuristics (weighted by field reliability).
	// We treat different fields as independent evidence channels and merge by weight.
	fields := []struct {
		name string
		val  string
		w    int
	}{
		{"org_domain", info.OrgDomain, 4},
		{"asn_domain", info.AsnDomain, 4},
		{"org", info.Org, 3},
		{"asn_owner", info.ASNOwner, 3},
		{"isp", info.ISP, 2},
	}

	cdnKW := []string{"cloudflare", "akamai", "fastly", "edgecast", "stackpath", "cloudfront", "cdn"}
	cloudKW := []string{"amazonaws", "amazon", "aws", "googleusercontent", "google", "gcp", "microsoft", "azure", "digitalocean", "linode", "vultr", "ovh", "hetzner", "leaseweb", "alibaba", "aliyun", "tencent", "huawei", "oracle", "oci"}
	privacyKW := []string{"vpn", "proxy", "tor", "exit", "wireguard", "openvpn", "socks"}

	weightedText := func(key string, kws []string, perW int, capAdd int) {
		add := 0
		matched := []string{}
		for _, f := range fields {
			v := strings.ToLower(strings.TrimSpace(f.val))
			if v == "" {
				continue
			}
			if containsAny(v, kws) {
				add += f.w * perW
				matched = append(matched, f.name)
			}
		}
		if add <= 0 {
			return
		}
		if add > capAdd {
			add = capAdd
		}
		score += add
		breakdown[key] = add
		if len(matched) > 0 {
			reasons = append(reasons, fmt.Sprintf("%s(+%d,%s)", key, add, strings.Join(matched, ",")))
		} else {
			reasons = append(reasons, fmt.Sprintf("%s(+%d)", key, add))
		}
	}

	weightedText("cdn_hint", cdnKW, 1, 8)
	weightedText("cloud_hint", cloudKW, 1, 6)
	weightedText("privacy_hint", privacyKW, 1, 6)

	// Country mismatch signals (if available)
	if info.CountryCode != "" && asnCountry != "" && strings.ToUpper(info.CountryCode) != strings.ToUpper(asnCountry) {
		score += 10
		breakdown["geo_asn_mismatch"] = 10
		reasons = append(reasons, "geo!=asn(+10)")
	}
	if info.CountryCode != "" && prefixCountry != "" && strings.ToUpper(info.CountryCode) != strings.ToUpper(prefixCountry) {
		score += 5
		breakdown["geo_prefix_mismatch"] = 5
		reasons = append(reasons, "geo!=prefix(+5)")
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, breakdown, strings.Join(reasons, "; ")
}

func computeRiskConfidence(info IPInfo, breakdown map[string]int) int {
	// Confidence is about evidence richness, not risk magnitude.
	conf := 30

	labels := []string{"tor", "vpn", "proxy", "hosting"}
	present := 0
	if info.signalTrueWeight != nil {
		for _, l := range labels {
			if info.signalTrueWeight[l] > 0 {
				present++
			}
		}
	}
	if present > 0 {
		conf += 25
	}
	if present >= 2 {
		conf += 10
	}
	if present >= 3 {
		conf += 5
	}

	// Text evidence present?
	textFields := []string{info.OrgDomain, info.AsnDomain, info.Org, info.ASNOwner, info.ISP}
	nonEmpty := 0
	for _, v := range textFields {
		if strings.TrimSpace(v) != "" {
			nonEmpty++
		}
	}
	if nonEmpty >= 2 {
		conf += 5
	}
	if nonEmpty >= 4 {
		conf += 5
	}

	// Strength of breakdown (excluding base).
	absSum := 0
	if breakdown != nil {
		for k, v := range breakdown {
			if k == "base" {
				continue
			}
			if v < 0 {
				absSum += -v
			} else {
				absSum += v
			}
		}
	}
	if absSum >= 20 {
		conf += 10
	}
	if absSum >= 40 {
		conf += 10
	}

	if conf > 95 {
		conf = 95
	}
	if conf < 0 {
		conf = 0
	}
	return conf
}

func computeHumanBotConfidence(info IPInfo, breakdown map[string]int) int {
	conf := 25

	// Explicit multi-source signals present?
	labels := []string{"tor", "vpn", "proxy", "hosting"}
	present := 0
	if info.signalTrueWeight != nil {
		for _, l := range labels {
			if info.signalTrueWeight[l] > 0 {
				present++
			}
		}
	}
	if present > 0 {
		conf += 25
	}
	if present >= 2 {
		conf += 10
	}
	if present >= 3 {
		conf += 5
	}

	// Strength of the breakdown (excluding base) indicates evidence richness.
	absSum := 0
	if breakdown != nil {
		for k, v := range breakdown {
			if k == "base" {
				continue
			}
			if v < 0 {
				absSum += -v
			} else {
				absSum += v
			}
		}
	}
	if absSum >= 25 {
		conf += 10
	}
	if absSum >= 45 {
		conf += 10
	}
	if absSum >= 70 {
		conf += 10
	}

	// If it's mostly heuristic keywords (weak), cap confidence.
	if breakdown != nil {
		strongKeys := 0
		for k := range breakdown {
			if k == "proxy" || k == "vpn" || k == "tor" || k == "hosting" || k == "proxy_ipapi" || k == "hosting_ipapi" {
				strongKeys++
			}
		}
		if strongKeys == 0 && absSum > 0 {
			if conf > 55 {
				conf = 55
			}
		}
	}

	if conf > 95 {
		conf = 95
	}
	if conf < 0 {
		conf = 0
	}
	return conf
}

// ---------------------------
// Utils
// ---------------------------

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// ---------------------------
// Multi-source signal merge helpers
// ---------------------------

var providerWeight = map[string]int{
	"ipapi.is":   4,
	"ipwho.is":   3,
	"ip-api.com": 2,
	"ipdata.co":  2,
	"ipapi.org":  1,
}

// ---------------------------
// ---------------------------

// fillDomainsFromRDNS tries to infer a reasonable domain from PTR records.
// This is only used as a *last resort* when both asn_domain/org_domain are empty.

// guessRootDomain is a tiny heuristic for taking the "root" domain from a hostname.
// It is NOT a full PSL implementation; it's only used to provide a clickable link.
func guessRootDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.Count(host, ".") == 0 {
		return ""
	}
	parts := strings.Split(host, ".")
	// remove empty parts
	pp := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			pp = append(pp, p)
		}
	}
	if len(pp) < 2 {
		return ""
	}
	// Common 2nd-level public suffix hints (very small set)
	secondLevel := map[string]struct{}{"co": {}, "com": {}, "net": {}, "org": {}, "gov": {}, "ac": {}, "edu": {}}
	last := pp[len(pp)-1]
	second := pp[len(pp)-2]
	// If TLD is country-code and second-level is common (e.g. co.uk), take last 3 labels.
	if len(last) == 2 {
		if _, ok := secondLevel[second]; ok && len(pp) >= 3 {
			return strings.Join(pp[len(pp)-3:], ".")
		}
	}
	return strings.Join(pp[len(pp)-2:], ".")
}

func noteSignal(info *IPInfo, signal string, src string, v bool) {
	if info == nil || signal == "" || src == "" {
		return
	}
	// Only track true evidence (we don't penalize false here).
	if !v {
		return
	}
	if info.signalTrueWeight == nil {
		info.signalTrueWeight = map[string]int{}
	}
	if info.signalTrueSources == nil {
		info.signalTrueSources = map[string]map[string]struct{}{}
	}
	// Weight by provider base (e.g. "ipdata.co:threat.is_proxy" -> "ipdata.co").
	base := src
	if i := strings.IndexByte(src, ':'); i > 0 {
		base = src[:i]
	}
	w := providerWeight[base]
	if w <= 0 {
		w = 1
	}
	info.signalTrueWeight[signal] += w
	set, ok := info.signalTrueSources[signal]
	if !ok {
		set = map[string]struct{}{}
		info.signalTrueSources[signal] = set
	}
	set[src] = struct{}{}
}

// setTrueSignal merges a boolean signal from a provider.
// We only care about positive evidence (true). True from a higher-weight provider
// can override the recorded source; multiple trues keep the strongest source.
// setTrueSignal merges a boolean signal from a provider.
// It supports both call styles:
//
//	setTrueSignal(&flag, &src, "ipwho.is")           // means v=true
//	setTrueSignal(&flag, &src, "ip-api.com", value)  // v=value
func setTrueSignal(dst **bool, dstSrc *string, src string, vOpt ...bool) {
	v := true
	if len(vOpt) > 0 {
		v = vOpt[0]
	}
	if !v {
		return
	}
	if dst == nil || dstSrc == nil {
		return
	}
	if *dst == nil {
		t := true
		*dst = &t
		*dstSrc = src
		return
	}
	if **dst == false {
		// upgrade false -> true
		t := true
		*dst = &t
		*dstSrc = src
		return
	}
	// already true: keep higher-weight source label
	if providerWeight[src] > providerWeight[*dstSrc] {
		*dstSrc = src
	}
}

func getEnv(key string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return ""
}

func getEnvOrDefault(key, def string) string {
	if v := strings.TrimSpace(getEnv(key)); v != "" {
		return v
	}
	return def
}

func getMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if mm, ok2 := v.(map[string]any); ok2 {
			return mm
		}
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return s
	}
	// common: json decodes numbers as float64
	switch vv := v.(type) {
	case float64:
		if vv == float64(int64(vv)) {
			return fmt.Sprintf("%d", int64(vv))
		}
		return fmt.Sprintf("%v", vv)
	case bool:
		if vv {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	// tolerate "true"/"false" strings
	if s, ok := v.(string); ok {
		s = strings.ToLower(strings.TrimSpace(s))
		return s == "true" || s == "1" || s == "yes"
	}
	return false
}

func getFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch vv := v.(type) {
	case float64:
		return vv
	case int:
		return float64(vv)
	case int64:
		return float64(vv)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(vv), 64)
		return f
	default:
		return 0
	}
}

func getInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch vv := v.(type) {
	case float64:
		return int(vv)
	case int:
		return vv
	case int64:
		return int(vv)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(vv, "AS")))
		return n
	default:
		return 0
	}
}

// ---------------------------

// normalizeASN coerces various ASN representations into the form "AS12345".
// Accepts: "AS12345", "12345", "AS12345 SomeName".
func normalizeASN(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	re := regexp.MustCompile(`(?i)\bAS\s*(\d+)\b|\b(\d+)\b`)
	m := re.FindStringSubmatch(s)
	if len(m) == 0 {
		return ""
	}
	num := ""
	if len(m) >= 2 && m[1] != "" {
		num = m[1]
	} else if len(m) >= 3 {
		num = m[2]
	}
	if num == "" {
		return ""
	}
	return "AS" + num
}

// parseASField parses fields like "AS15169 Google LLC".
// Returns ("AS15169", "Google LLC").
func parseASField(asField string) (string, string) {
	asField = strings.TrimSpace(asField)
	if asField == "" {
		return "", ""
	}
	re := regexp.MustCompile(`(?i)^AS\s*(\d+)(?:\s+(.*))?$`)
	m := re.FindStringSubmatch(asField)
	if len(m) == 0 {
		asn := normalizeASN(asField)
		owner := strings.TrimSpace(asField)
		if asn != "" {
			owner = strings.TrimSpace(strings.TrimPrefix(owner, asn))
		}
		return asn, owner
	}
	asn := "AS" + m[1]
	owner := ""
	if len(m) >= 3 {
		owner = strings.TrimSpace(m[2])
	}
	return asn, owner
}

// ---------------------------
