package metrics

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, m *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	return rec.Body.String()
}

func TestCounters(t *testing.T) {
	m := New()
	m.ObserveRequest("claude", "anthropic")
	m.ObserveRequest("claude", "anthropic")
	m.ObserveRequest("codex", "openai")
	m.ObserveTiers(map[string]int{"redacted": 2, "public": 1})
	m.ObserveRedactions(map[string]int{"ipv4": 3, "email": 1})
	m.IncBlocked(2)
	m.IncFailClosed()
	m.IncUpstreamError()
	m.AddCacheHits(4)

	out := scrape(t, m)
	for _, want := range []string{
		`tidegate_requests_total{agent="claude",provider="anthropic"} 2`,
		`tidegate_requests_total{agent="codex",provider="openai"} 1`,
		`tidegate_redactions_total{pattern="ipv4"} 3`,
		`tidegate_blocks_total{tier="redacted"} 2`,
		`tidegate_requests_blocked_total 1`,
		`tidegate_blocks_blocked_total 2`,
		`tidegate_fail_closed_total 1`,
		`tidegate_upstream_errors_total 1`,
		`tidegate_redaction_cache_hits_total 4`,
		`# TYPE tidegate_requests_total counter`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelEscaping(t *testing.T) {
	m := New()
	m.ObserveRequest("agent\"with\\quote\nnewline", "openai")
	out := scrape(t, m)
	if !strings.Contains(out, `agent="agent\"with\\quote\nnewline"`) {
		t.Fatalf("label not escaped:\n%s", out)
	}
	if strings.Count(out, "tidegate_requests_total{") != 1 {
		t.Fatalf("expected one series:\n%s", out)
	}
}

func TestVaultStatsGauges(t *testing.T) {
	m := New()
	m.SetVaultStats(func() (int64, int64, error) { return 7, 3, nil })
	out := scrape(t, m)
	if !strings.Contains(out, "tidegate_vault_tokens 7") || !strings.Contains(out, "tidegate_vault_cache_entries 3") {
		t.Fatalf("vault gauges missing:\n%s", out)
	}
}

func TestStatsJSON(t *testing.T) {
	m := New()
	m.ObserveRequest("claude", "anthropic")
	m.ObserveRedactions(map[string]int{"ipv4": 2})
	m.IncBlocked(1)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/stats", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var got statsJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v (%s)", err, rec.Body.String())
	}
	if got.Requests["claude/anthropic"] != 1 || got.Redactions["ipv4"] != 2 || got.BlockedRequests != 1 {
		t.Fatalf("stats = %+v", got)
	}
}

func TestNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	New().Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
}
