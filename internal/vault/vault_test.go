package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if !strings.HasPrefix(a, "[TG:IP:1:") || a != b {
		t.Fatalf("want stable [TG:IP:1:<mac>], got %q and %q", a, b)
	}

	other, err := v.Token("s1", "IP", "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(other, "[TG:IP:2:") {
		t.Fatalf("want [TG:IP:2:<mac>], got %q", other)
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	v := newTestVault(t, time.Hour)

	t1, _ := v.Token("s1", "IP", "203.0.113.42")
	t2, _ := v.Token("s2", "IP", "198.51.100.7")
	if !strings.HasPrefix(t1, "[TG:IP:1:") || !strings.HasPrefix(t2, "[TG:IP:1:") || t1 == t2 {
		t.Fatalf("each session numbers from 1 with its own MAC: got %q, %q", t1, t2)
	}

	got, ok, err := v.Lookup("s1", t1)
	if err != nil || !ok || got != "203.0.113.42" {
		t.Fatalf("session s1 lookup = %q, %v, %v", got, ok, err)
	}
	got, ok, _ = v.Lookup("s2", t2)
	if !ok || got != "198.51.100.7" {
		t.Fatalf("session s2 lookup = %q, %v", got, ok)
	}
	// s3 has no mapping at all: no cross-session leakage.
	if _, ok, _ := v.Lookup("s3", t1); ok {
		t.Fatal("unknown session resolved a token")
	}
}

func TestTokenExpiry(t *testing.T) {
	v := newTestVault(t, time.Minute)
	base := time.Now()
	v.now = func() time.Time { return base }

	token, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Lookup("s1", token); !ok {
		t.Fatal("token should be live before TTL")
	}

	v.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok, _ := v.Lookup("s1", token); ok {
		t.Fatal("expired token still resolves")
	}
	n, err := v.Sweep()
	if err != nil || n == 0 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
}

func TestSessionsForTokensOwnedBy(t *testing.T) {
	v := newTestVault(t, time.Hour)
	t1, _ := v.Token("s1", "IP", "203.0.113.42")
	t2, _ := v.Token("s2", "EMAIL", "a@b.c")
	v.ClaimSession("s1", "alice")
	v.ClaimSession("s2", "bob")

	got, err := v.SessionsForTokensOwnedBy([]string{t1, t2}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "s1" {
		t.Fatalf("alice should only see s1, got %v", got)
	}
	got, _ = v.SessionsForTokensOwnedBy([]string{t1}, "mallory")
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
	tok, _ := v.Token("h:deadbeefdeadbeef", "IP", "203.0.113.42")
	v.ClaimSession("h:deadbeefdeadbeef", "claude")

	body, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "earlier we saw " + tok + ", right?"},
			map[string]interface{}{"role": "user", "content": "continue"},
		},
	})
	got := DeriveSession("", "claude", body, v)
	if got != "h:deadbeefdeadbeef" {
		t.Fatalf("want adopted session, got %q", got)
	}
}

// TestAdoptionRequiresSameIdentity is the regression test for the session
// oracle: guessing [TG:IP:1:00000000] must not let another principal adopt a session
// and harvest the original.
func TestAdoptionRequiresSameIdentity(t *testing.T) {
	v := newTestVault(t, time.Hour)
	tok, _ := v.Token("h:victim", "IP", "203.0.113.42")
	v.ClaimSession("h:victim", "client:alice")

	body, _ := json.Marshal(map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "echo " + tok},
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
	got := TokensIn("a [TG:IP:1:00000000] b [TG:IP:1:00000000] c [TG:EMAIL:12:00000000] d [TG:ip:1]")
	if len(got) != 2 || got[0] != "[TG:IP:1:00000000]" || got[1] != "[TG:EMAIL:12:00000000]" {
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

// TestExpiredTokenIsNotReissued covers the TTL bug: an expired row used to be
// returned again, so the value kept an unusable token instead of a fresh one.
func TestExpiredTokenIsNotReissued(t *testing.T) {
	v := newTestVault(t, time.Minute)
	base := time.Now()
	v.now = func() time.Time { return base }

	first, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return base.Add(2 * time.Minute) }

	second, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("expired token was reissued: %q", second)
	}
	if _, ok, _ := v.Lookup("s1", second); !ok {
		t.Fatal("fresh token should resolve")
	}
}

// TestTokenShapeIsUnguessable ensures the MAC suffix is not the stateless
// placeholder and that a forged label does not resolve.
func TestTokenShapeIsUnguessable(t *testing.T) {
	v := newTestVault(t, time.Hour)
	tok, err := v.Token("s1", "IP", "203.0.113.42")
	if err != nil {
		t.Fatal(err)
	}
	if !tokenRe.MatchString(tok) {
		t.Fatalf("token shape: %q", tok)
	}
	if tok == "[TG:IP:1:00000000]" {
		t.Fatal("vault token must not use the stateless placeholder suffix")
	}
	if _, ok, _ := v.Lookup("s1", "[TG:IP:1:00000000]"); ok {
		t.Fatal("forged token resolved")
	}
}

func TestFingerprintIncludesSystem(t *testing.T) {
	v := newTestVault(t, time.Hour)
	mk := func(system string) []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"system": system,
			"messages": []interface{}{
				map[string]interface{}{"role": "user", "content": "same opening"},
			},
		})
		return b
	}
	a := DeriveSession("", "local", mk("you are helpful"), v)
	b := DeriveSession("", "local", mk("you are a pirate"), v)
	if a == b {
		t.Fatal("different system prompts must produce different sessions")
	}
}
