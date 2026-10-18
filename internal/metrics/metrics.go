// Package metrics implements Tidegate's Prometheus/JSON metrics registry.
//
// The gateway's headline number is not tokens saved but leaks prevented:
// values redacted, blocks refused, and requests that failed closed. The
// registry keeps those counters in-process and exposes them on a separate
// listener so scraping never shares a socket with proxied traffic.
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry holds all gateway counters.
type Registry struct {
	mu sync.Mutex

	start time.Time

	requests   map[agentProvider]int64
	redactions map[string]int64
	tiers      map[string]int64

	blockedRequests int64
	blockedBlocks   int64
	failClosed      int64
	upstreamErrors  int64
	cacheHits       int64

	// vaultStats is optional; when set, /metrics includes live vault gauges.
	vaultStats func() (tokens, cached int64, err error)
}

type agentProvider struct {
	agent    string
	provider string
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{
		start:      time.Now(),
		requests:   map[agentProvider]int64{},
		redactions: map[string]int64{},
		tiers:      map[string]int64{},
	}
}

// SetVaultStats wires live vault gauges into the output.
func (m *Registry) SetVaultStats(fn func() (int64, int64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vaultStats = fn
}

// ObserveRequest counts one proxied request.
func (m *Registry) ObserveRequest(agent, provider string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[agentProvider{agent, provider}]++
}

// ObserveTiers counts classified blocks by tier.
func (m *Registry) ObserveTiers(tiers map[string]int) {
	if len(tiers) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for tier, n := range tiers {
		m.tiers[tier] += int64(n)
	}
}

// ObserveRedactions counts redacted values by pattern.
func (m *Registry) ObserveRedactions(summary map[string]int) {
	if len(summary) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, n := range summary {
		m.redactions[name] += int64(n)
	}
}

// IncBlocked records a request that contained blocked content and how many
// blocks were blocked.
func (m *Registry) IncBlocked(blocks int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockedRequests++
	m.blockedBlocks += int64(blocks)
}

// IncFailClosed records a request refused because processing failed.
func (m *Registry) IncFailClosed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failClosed++
}

// IncUpstreamError records a failed upstream call.
func (m *Registry) IncUpstreamError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamErrors++
}

// AddCacheHits records content-addressed redaction cache hits.
func (m *Registry) AddCacheHits(n int) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheHits += int64(n)
}

// Handler returns an http.Handler serving /metrics and /stats.
func (m *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics", "/":
			m.writePrometheus(w)
		case "/stats":
			m.writeJSON(w)
		default:
			http.NotFound(w, r)
		}
	})
}

func (m *Registry) writePrometheus(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder
	writeMetric(&b, "tidegate_requests_total", "counter", "Proxied LLM API requests.", func() {
		keys := make([]agentProvider, 0, len(m.requests))
		for k := range m.requests {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].agent != keys[j].agent {
				return keys[i].agent < keys[j].agent
			}
			return keys[i].provider < keys[j].provider
		})
		for _, k := range keys {
			fmt.Fprintf(&b, "tidegate_requests_total{agent=%q,provider=%q} %d\n",
				k.agent, k.provider, m.requests[k])
		}
	})

	writeMetric(&b, "tidegate_redactions_total", "counter", "Values replaced, by pattern.", func() {
		names := make([]string, 0, len(m.redactions))
		for n := range m.redactions {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "tidegate_redactions_total{pattern=%q} %d\n", n, m.redactions[n])
		}
	})

	writeMetric(&b, "tidegate_blocks_total", "counter", "Content blocks classified, by tier.", func() {
		names := make([]string, 0, len(m.tiers))
		for n := range m.tiers {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "tidegate_blocks_total{tier=%q} %d\n", n, m.tiers[n])
		}
	})

	writeSimple(&b, "tidegate_requests_blocked_total", "counter", "Requests containing blocked content.", m.blockedRequests)
	writeSimple(&b, "tidegate_blocks_blocked_total", "counter", "Individual content blocks blocked.", m.blockedBlocks)
	writeSimple(&b, "tidegate_fail_closed_total", "counter", "Requests refused because processing failed.", m.failClosed)
	writeSimple(&b, "tidegate_upstream_errors_total", "counter", "Failed upstream API calls.", m.upstreamErrors)
	writeSimple(&b, "tidegate_redaction_cache_hits_total", "counter", "Blocks served from the redaction cache.", m.cacheHits)
	writeSimple(&b, "tidegate_uptime_seconds", "gauge", "Process uptime in seconds.", int64(time.Since(m.start).Seconds()))

	if m.vaultStats != nil {
		if tokens, cached, err := m.vaultStats(); err == nil {
			writeSimple(&b, "tidegate_vault_tokens", "gauge", "Live token mappings in the vault.", tokens)
			writeSimple(&b, "tidegate_vault_cache_entries", "gauge", "Live redaction cache entries.", cached)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func writeMetric(b *strings.Builder, name, typ, help string, body func()) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	body()
}

func writeSimple(b *strings.Builder, name, typ, help string, v int64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, v)
}

type statsJSON struct {
	UptimeSeconds     int64            `json:"uptime_seconds"`
	Requests          map[string]int64 `json:"requests"`
	Redactions        map[string]int64 `json:"redactions"`
	Tiers             map[string]int64 `json:"tiers"`
	BlockedRequests   int64            `json:"blocked_requests"`
	BlockedBlocks     int64            `json:"blocked_blocks"`
	FailClosed        int64            `json:"fail_closed"`
	UpstreamErrors    int64            `json:"upstream_errors"`
	CacheHits         int64            `json:"redaction_cache_hits"`
	VaultTokens       int64            `json:"vault_tokens"`
	VaultCacheEntries int64            `json:"vault_cache_entries"`
}

func (m *Registry) writeJSON(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := statsJSON{
		UptimeSeconds:   int64(time.Since(m.start).Seconds()),
		Requests:        map[string]int64{},
		Redactions:      map[string]int64{},
		Tiers:           map[string]int64{},
		BlockedRequests: m.blockedRequests,
		BlockedBlocks:   m.blockedBlocks,
		FailClosed:      m.failClosed,
		UpstreamErrors:  m.upstreamErrors,
		CacheHits:       m.cacheHits,
	}
	for k, v := range m.requests {
		out.Requests[k.agent+"/"+k.provider] = v
	}
	for k, v := range m.redactions {
		out.Redactions[k] = v
	}
	for k, v := range m.tiers {
		out.Tiers[k] = v
	}
	if m.vaultStats != nil {
		if tokens, cached, err := m.vaultStats(); err == nil {
			out.VaultTokens = tokens
			out.VaultCacheEntries = cached
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
