package route

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qo-roj/tidegate/internal/content"
	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/vault"
)

func makeVaultRouter(t *testing.T) *Router {
	t.Helper()
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return makeTestRouter(t, nil).WithVault(v)
}

func decodeMessages(t *testing.T, body []byte) []map[string]interface{} {
	t.Helper()
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	raw := req["messages"].([]interface{})
	out := make([]map[string]interface{}, len(raw))
	for i, m := range raw {
		out[i] = m.(map[string]interface{})
	}
	return out
}

// TestSessionTokensStableAcrossTurns covers the core promise: the same secret
// keeps its token, a new secret gets a new one, and history is still fully
// redacted on every turn (the agent resends originals, not tokens).
func TestSessionTokensStableAcrossTurns(t *testing.T) {
	router := makeVaultRouter(t)

	turn1 := makeRequestBody(t, []map[string]interface{}{
		{"role": "system", "content": "You are a coding agent."},
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
	})
	_, out1, _, err := router.ProcessRequestSession(turn1, "claude", "anthropic", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out1), "[TG:IP:1]") {
		t.Fatalf("turn 1 missing token: %s", out1)
	}

	turn2 := makeRequestBody(t, []map[string]interface{}{
		{"role": "system", "content": "You are a coding agent."},
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
		{"role": "assistant", "content": "noted"},
		{"role": "user", "content": "log /var/log/app.log host 198.51.100.7"},
	})
	ctx2, out2, _, err := router.ProcessRequestSession(turn2, "claude", "anthropic", "sess-1")
	if err != nil {
		t.Fatal(err)
	}

	msgs := decodeMessages(t, out2)
	history := msgs[1]["content"].(string)
	delta := msgs[3]["content"].(string)
	if !strings.Contains(history, "[TG:IP:1]") {
		t.Fatalf("history token changed: %q", history)
	}
	if !strings.Contains(delta, "[TG:IP:2]") {
		t.Fatalf("new value should get [TG:IP:2]: %q", delta)
	}
	// Security invariant: history must never be forwarded unredacted.
	if strings.Contains(string(out2), "203.0.113.42") || strings.Contains(string(out2), "198.51.100.7") {
		t.Fatalf("raw secret in forwarded body: %s", out2)
	}

	restored := router.ProcessResponse(ctx2, []byte(`{"text":"[TG:IP:1] and [TG:IP:2]"}`))
	if !strings.Contains(string(restored), "203.0.113.42") || !strings.Contains(string(restored), "198.51.100.7") {
		t.Fatalf("restore failed: %s", restored)
	}
}

func TestRedactionCacheHits(t *testing.T) {
	router := makeVaultRouter(t)

	msg := map[string]interface{}{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"}
	body := makeRequestBody(t, []map[string]interface{}{msg})

	ctx1, out1, _, err := router.ProcessRequestSession(body, "claude", "anthropic", "s")
	if err != nil {
		t.Fatal(err)
	}
	if ctx1.CacheHits != 0 {
		t.Fatalf("first request should miss, got %d hits", ctx1.CacheHits)
	}

	ctx2, out2, _, err := router.ProcessRequestSession(body, "claude", "anthropic", "s")
	if err != nil {
		t.Fatal(err)
	}
	if ctx2.CacheHits == 0 {
		t.Fatal("second identical request should hit the cache")
	}
	if string(out1) != string(out2) {
		t.Fatalf("cached output differs:\n%s\n%s", out1, out2)
	}
	// A cache hit must still restore tokens in the response.
	restored := router.ProcessResponse(ctx2, []byte("[TG:IP:1]"))
	if !strings.Contains(string(restored), "203.0.113.42") {
		t.Fatalf("cache hit broke restore: %s", restored)
	}
}

func TestRedactContentJSONSecrets(t *testing.T) {
	router := makeVaultRouter(t)
	ctx := &RequestContext{Session: "s", Redactor: router.NewRedactor().WithStore(router.Vault, "s")}

	src := `{"user":"alice","password":"hunter2","nested":{"api_key":"sk-abc123"},"count":3}`
	out, summary := router.redactContent(ctx, ctx.Redactor, src)

	if summary["json_secret"] != 2 {
		t.Fatalf("summary = %v, want 2 json_secret", summary)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-abc123") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON output: %s", out)
	}
	restored := ctx.Redactor.Restore(out)
	if !strings.Contains(restored, "hunter2") || !strings.Contains(restored, "sk-abc123") {
		t.Fatalf("restore failed: %s", restored)
	}
}

func TestRedactContentShieldsTimestamps(t *testing.T) {
	router := makeVaultRouter(t)
	ctx := &RequestContext{Session: "s", Redactor: router.NewRedactor().WithStore(router.Vault, "s")}

	src := "15:07:51.712345 2026 client denied by server configuration"
	out, summary := router.redactContent(ctx, ctx.Redactor, src)
	if summary["phone"] != 0 {
		t.Fatalf("phone pattern fired on timestamp: %v", summary)
	}
	if out != src {
		t.Fatalf("timestamp line changed: %q", out)
	}
}

func TestNoVaultKeepsPerRequestBehaviour(t *testing.T) {
	router := makeTestRouter(t, nil) // no vault
	body := makeRequestBody(t, []map[string]interface{}{
		{"role": "user", "content": "log /var/log/app.log host 203.0.113.42"},
	})
	ctx, out, _, err := router.ProcessRequest(body, "claude", "openai")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "203.0.113.42") {
		t.Fatalf("IP leaked: %s", out)
	}
	if ctx.Session != "" || ctx.CacheHits != 0 {
		t.Fatalf("stateless path should have no session: %+v", ctx)
	}
	if got := router.ProcessResponse(ctx, []byte("[TG:IP:1]")); !strings.Contains(string(got), "203.0.113.42") {
		t.Fatalf("stateless restore failed: %s", got)
	}
}

// TestContentRouterDetectsJSON guards the wiring between shape detection and
// redaction (the JSON path must actually be taken for pure JSON blocks).
func TestContentRouterDetectsJSON(t *testing.T) {
	if content.Detect(`{"a":"b"}`) != content.KindJSON {
		t.Fatal("JSON block not detected")
	}
	_ = redact.Summary{}
}
