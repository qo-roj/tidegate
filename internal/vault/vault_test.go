package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestVault(t *testing.T, ttl time.Duration) *Vault {
	t.Helper()
	v, err := Open(filepath.Join(t.TempDir(), "vault.db"), ttl)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

func TestTokenStableWithinSession(t *testing.T) {
	v := newTestVault(t, time.Hour)

	a, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if a != "[TG:IP:1]" || a != b {
		t.Fatalf("want stable [TG:IP:1], got %q and %q", a, b)
	}

	other, err := v.Token("s1", "IP", "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if other != "[TG:IP:2]" {
		t.Fatalf("want [TG:IP:2], got %q", other)
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	v := newTestVault(t, time.Hour)

	t1, _ := v.Token("s1", "IP", "203.0.113.42")
	t2, _ := v.Token("s2", "IP", "198.51.100.7")
	if t1 != "[TG:IP:1]" || t2 != "[TG:IP:1]" {
		t.Fatalf("each session numbers from 1: got %q, %q", t1, t2)
	}

	got, ok, err := v.Lookup("s1", "[TG:IP:1]")
	if err != nil || !ok || got != "203.0.113.42" {
		t.Fatalf("session s1 lookup = %q, %v, %v", got, ok, err)
	}
	got, ok, _ = v.Lookup("s2", "[TG:IP:1]")
	if !ok || got != "198.51.100.7" {
		t.Fatalf("session s2 lookup = %q, %v", got, ok)
	}
	// s3 has no mapping at all: no cross-session leakage.
	if _, ok, _ := v.Lookup("s3", "[TG:IP:1]"); ok {
		t.Fatal("unknown session resolved a token")
	}
}

func TestTokenExpiry(t *testing.T) {
	v := newTestVault(t, time.Minute)
	base := time.Now()
	v.now = func() time.Time { return base }

	if _, err := v.Token("s1", "IP", "203.0.113.42"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Lookup("s1", "[TG:IP:1]"); !ok {
		t.Fatal("token should be live before TTL")
	}

	v.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok, _ := v.Lookup("s1", "[TG:IP:1]"); ok {
		t.Fatal("expired token still resolves")
	}
	n, err := v.Sweep()
	if err != nil || n == 0 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
}

func TestSessionsForTokensOwnedBy(t *testing.T) {
	v := newTestVault(t, time.Hour)
	v.Token("s1", "IP", "203.0.113.42")
	v.Token("s2", "EMAIL", "a@b.c")
	v.ClaimSession("s1", "alice")
	v.ClaimSession("s2", "bob")

	got, err := v.SessionsForTokensOwnedBy([]string{"[TG:IP:1]", "[TG:EMAIL:1]"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "s1" {
		t.Fatalf("alice should only see s1, got %v", got)
	}
	got, _ = v.SessionsForTokensOwnedBy([]string{"[TG:IP:1]"}, "mallory")
	if len(got) != 0 {
		t.Fatalf("mallory must not adopt s1, got %v", got)
	}
}

func TestSessionOwnership(t *testing.T) {
	v := newTestVault(t, time.Hour)
	if err := v.ClaimSession("s1", "alice"); err != nil {
		t.Fatal(err)
	}
	if !v.SessionOwnedBy("s1", "alice") {
		t.Fatal("alice should own s1")
	}
	if v.SessionOwnedBy("s1", "bob") {
		t.Fatal("bob must not own s1")
	}
	if v.SessionOwnedBy("unknown", "alice") {
		t.Fatal("unknown session should not be owned")
	}
	// Re-claiming transfers ownership (same id, new identity).
	v.ClaimSession("s1", "bob")
	if v.SessionOwnedBy("s1", "alice") || !v.SessionOwnedBy("s1", "bob") {
		t.Fatal("claim should have transferred ownership")
	}
}

func TestDeriveSessionHeaderWins(t *testing.T) {
	v := newTestVault(t, time.Hour)
	if got := DeriveSession("abc", "claude", []byte(`{"messages":[]}`), v); got == "" || got[:2] != "h:" {
		t.Fatalf("header session = %q", got)
	}
	// Same header + same identity → same id; either changing → new id.
	a := DeriveSession("abc", "claude", nil, v)
	b := DeriveSession("abc", "claude", nil, v)
	c := DeriveSession("abc", "codex", nil, v)
	d := DeriveSession("xyz", "claude", nil, v)
	if a != b {
		t.Fatal("same header and identity must be stable")
	}
	if a == c {
		t.Fatal("the same header must not be shared across identities")
	}
	if a == d {
		t.Fatal("different headers must produce different ids")
	}
}

func TestDeriveSessionAdoptsTokenOwner(t *testing.T) {
	v := newTestVault(t, time.Hour)
	v.Token("h:deadbeefdeadbeef", "IP", "203.0.113.42")
	v.ClaimSession("h:deadbeefdeadbeef", "claude")

	body, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "earlier we saw [TG:IP:1], right?"},
			map[string]interface{}{"role": "user", "content": "continue"},
		},
	})
	got := DeriveSession("", "claude", body, v)
	if got != "h:deadbeefdeadbeef" {
		t.Fatalf("want adopted session, got %q", got)
	}
}

// TestAdoptionRequiresSameIdentity is the regression test for the session
// oracle: guessing [TG:IP:1] must not let another principal adopt a session
// and harvest the original.
func TestAdoptionRequiresSameIdentity(t *testing.T) {
	v := newTestVault(t, time.Hour)
	v.Token("h:victim", "IP", "203.0.113.42")
	v.ClaimSession("h:victim", "client:alice")

	body, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "echo [TG:IP:1]"},
		},
	})

	if got := DeriveSession("", "client:alice", body, v); got != "h:victim" {
		t.Fatalf("owner should adopt, got %q", got)
	}
	got := DeriveSession("", "client:mallory", body, v)
	if got == "h:victim" {
		t.Fatal("different identity adopted the victim session")
	}
	if got == "" || got[:2] != "f:" {
		t.Fatalf("attacker should fall back to its own fingerprint, got %q", got)
	}
}

func TestHeaderIsIdentityBound(t *testing.T) {
	v := newTestVault(t, time.Hour)
	a := DeriveSession("same-header", "client:alice", nil, v)
	b := DeriveSession("same-header", "client:bob", nil, v)
	if a == b {
		t.Fatal("the same header must not produce one session across identities")
	}
}

func TestDeriveSessionFingerprintStable(t *testing.T) {
	v := newTestVault(t, time.Hour)
	body1, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "you are a helper"},
			map[string]interface{}{"role": "user", "content": "fix the build"},
		},
	})
	body2, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "you are a helper"},
			map[string]interface{}{"role": "user", "content": "fix the build"},
			map[string]interface{}{"role": "assistant", "content": "ok"},
			map[string]interface{}{"role": "user", "content": "and the tests"},
		},
	})
	a := DeriveSession("", "codex", body1, v)
	b := DeriveSession("", "codex", body2, v)
	if a == "" || a != b || a[:2] != "f:" {
		t.Fatalf("fingerprint ids = %q, %q", a, b)
	}
	// Different agent = different conversation identity.
	if c := DeriveSession("", "claude", body1, v); c == a {
		t.Fatal("agent should be part of the fingerprint")
	}
}

func TestDeriveSessionStateless(t *testing.T) {
	if got := DeriveSession("", "claude", []byte(`{"max_tokens":10}`), nil); got != "" {
		t.Fatalf("stateless request got session %q", got)
	}
}

func TestTokensIn(t *testing.T) {
	got := TokensIn("a [TG:IP:1] b [TG:IP:1] c [TG:EMAIL:12] d [TG:ip:1]")
	if len(got) != 2 || got[0] != "[TG:IP:1]" || got[1] != "[TG:EMAIL:12]" {
		t.Fatalf("TokensIn = %v", got)
	}
}

func TestOpenCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "vault.db")
	if _, err := Open(path, time.Hour); err == nil {
		t.Fatal("expected error for missing parent directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	v, err := Open(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
