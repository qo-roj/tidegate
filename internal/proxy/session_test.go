package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qo-roj/tidegate/internal/metrics"
	"github.com/qo-roj/tidegate/internal/vault"
)

// TestProxySessionStableTokens drives two turns through the real HTTP handler
// and checks that history stays redacted, tokens stay stable, and the session
// header never reaches the upstream.
func TestProxySessionStableTokens(t *testing.T) {
	srv, upstream := makeTestServer(t)
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	srv.Vault = v

	turn1 := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
	})
	req := makeChatRequest(t, turn1, "openai")
	req.Header.Set("X-Tidegate-Session", "conv-1")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn 1 status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(upstream.receivedBody), "[TG:IP:1:00000000]") {
		t.Fatalf("turn 1 upstream body: %s", upstream.receivedBody)
	}
	if upstream.receivedHeaders.Get("X-Tidegate-Session") != "" {
		t.Fatal("session header leaked upstream")
	}

	turn2 := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
		{"role": "assistant", "content": "noted"},
		{"role": "user", "content": "log /var/log/app.log host 198.51.100.7"},
	})
	req = makeChatRequest(t, turn2, "openai")
	req.Header.Set("X-Tidegate-Session", "conv-1")
	rec = httptest.NewRecorder()
	srv.handleProxy(rec, req)
	if rec.Code != 200 {
		t.Fatalf("turn 2 status %d: %s", rec.Code, rec.Body.String())
	}

	var sent struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(upstream.receivedBody, &sent); err != nil {
		t.Fatalf("upstream body: %v (%s)", err, upstream.receivedBody)
	}
	if !strings.Contains(sent.Messages[0].Content, "[TG:IP:1:00000000]") {
		t.Fatalf("history token changed: %q", sent.Messages[0].Content)
	}
	if !strings.Contains(sent.Messages[2].Content, "[TG:IP:2:00000000]") {
		t.Fatalf("new value token wrong: %q", sent.Messages[2].Content)
	}
	if strings.Contains(string(upstream.receivedBody), "203.0.113.42") {
		t.Fatalf("history forwarded unredacted: %s", upstream.receivedBody)
	}
}

// TestProxySessionInferredFromTokens covers clients that cannot set a custom
// header (raw SDKs): the conversation's own token identifies it.
func TestProxySessionInferredFromTokens(t *testing.T) {
	srv, upstream := makeTestServer(t)
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	srv.Vault = v

	first := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
	})
	srv.handleProxy(httptest.NewRecorder(), makeChatRequest(t, first, "openai"))

	second := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
		{"role": "assistant", "content": "the host was [TG:IP:1:00000000]"},
		{"role": "user", "content": "and the new one?"},
	})
	req := makeChatRequest(t, second, "openai")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)

	var sent struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(upstream.receivedBody, &sent); err != nil {
		t.Fatalf("upstream body: %v", err)
	}
	if !strings.Contains(sent.Messages[1].Content, "[TG:IP:1:00000000]") {
		t.Fatalf("assistant history token was re-mapped: %q", sent.Messages[1].Content)
	}
}

func TestProxyMetrics(t *testing.T) {
	srv, _ := makeTestServer(t)
	reg := metrics.New()
	srv.Metrics = reg

	body := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "plain question"},
	})
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, makeChatRequest(t, body, "openai"))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}

	stats := httptest.NewRecorder()
	reg.Handler().ServeHTTP(stats, httptest.NewRequest("GET", "/stats", nil))
	if !strings.Contains(stats.Body.String(), `"requests"`) {
		t.Fatalf("stats body: %s", stats.Body.String())
	}

	prom := httptest.NewRecorder()
	reg.Handler().ServeHTTP(prom, httptest.NewRequest("GET", "/metrics", nil))
	out := prom.Body.String()
	for _, want := range []string{
		"tidegate_requests_total{agent=\"test-agent\",provider=\"openai\"} 1",
		"tidegate_uptime_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q in:\n%s", want, out)
		}
	}
}

// TestGatewayClientCannotAdoptAnotherClientsSession is the regression test for
// the session oracle: tokens are guessable, so ownership must be bound to the
// authenticated client key.
func TestGatewayClientCannotAdoptAnotherClientsSession(t *testing.T) {
	srv, upstream := makeTestServer(t)
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	srv.Vault = v
	srv.Clients = []Client{
		{Name: "alice", Key: "key-a"},
		{Name: "bob", Key: "key-b"},
	}

	aliceBody := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
	})
	req := makeChatRequest(t, aliceBody, "openai")
	req.Header.Set("X-Tidegate-Key", "key-a")
	req.Header.Set("X-Tidegate-Session", "shared-name")
	rec := httptest.NewRecorder()
	srv.handleProxy(rec, req)
	if rec.Code != 200 {
		t.Fatalf("alice status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(upstream.receivedBody), "[TG:IP:1:00000000]") {
		t.Fatalf("alice body: %s", upstream.receivedBody)
	}

	// Bob guesses the token and even reuses the session header name.
	upstream.responseBody = `{"text":"the host is [TG:IP:1:00000000]"}`
	bobBody := makeChatBody(t, []map[string]interface{}{
		{"role": "user", "content": "what is [TG:IP:1:00000000]?"},
	})
	req = makeChatRequest(t, bobBody, "openai")
	req.Header.Set("X-Tidegate-Key", "key-b")
	req.Header.Set("X-Tidegate-Session", "shared-name")
	rec = httptest.NewRecorder()
	srv.handleProxy(rec, req)
	if rec.Code != 200 {
		t.Fatalf("bob status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "203.0.113.42") {
		t.Fatalf("bob harvested alice's value: %s", rec.Body.String())
	}
}
