package redact_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/vault"
)

var tokRe = regexp.MustCompile(`\[TG:[A-Z0-9_]+:[0-9]+:[0-9a-f]{8}\]`)

func openVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.db"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

// TestCrossTurnTokenCollision is the regression test for the bug where a
// per-request redactor restarted numbering at 1, so a token echoed from turn 1
// resolved to a *different* secret in turn 2.
func TestCrossTurnTokenCollision(t *testing.T) {
	v := openVault(t)

	r1 := redact.New().WithStore(v, "session-a")
	out1, _ := r1.Redact("host is 203.0.113.42")
	token1 := tokRe.FindString(out1)
	if !strings.HasPrefix(token1, "[TG:IP:1:") {
		t.Fatalf("turn 1 = %q, want [TG:IP:1:<mac>]", out1)
	}

	// Turn 2: history carries the old token; a new, different secret arrives.
	r2 := redact.New().WithStore(v, "session-a")
	r2.NoteTokens(out1)
	out2, _ := r2.Redact("history: " + out1 + " ; new host is 198.51.100.7")
	token2 := ""
	for _, tok := range tokRe.FindAllString(out2, -1) {
		if strings.HasPrefix(tok, "[TG:IP:2:") {
			token2 = tok
		}
	}
	if token2 == "" {
		t.Fatalf("turn 2 = %q, want the new value to get [TG:IP:2:<mac>]", out2)
	}

	restored := redact.NewTokenMatcher(r2).Restore("history: " + token1 + " ; new: " + token2)
	want := "history: 203.0.113.42 ; new: 198.51.100.7"
	if restored != want {
		t.Fatalf("restore = %q, want %q", restored, want)
	}
}

// TestHistoricalTokensRemainResolvable covers the case where a turn contains
// only a new message but the model's answer refers to a token from history.
func TestHistoricalTokensRemainResolvable(t *testing.T) {
	v := openVault(t)

	r1 := redact.New().WithStore(v, "s")
	ipOut, _ := r1.Redact("the host is 203.0.113.42")
	mailOut, _ := r1.Redact("mail admin@example.com")
	ipTok := tokRe.FindString(ipOut)
	mailTok := tokRe.FindString(mailOut)

	r2 := redact.New().WithStore(v, "s")
	r2.NoteTokens("earlier: " + ipTok + " and " + mailTok)
	r2.Redact("what was that host again?")

	got := redact.NewTokenMatcher(r2).Restore(ipTok + " / " + mailTok)
	if got != "203.0.113.42 / admin@example.com" {
		t.Fatalf("restore = %q", got)
	}
}

// TestUnseenTokensAreNotRestored makes sure the gateway cannot be used as an
// oracle: a token the request never carried stays opaque.
func TestUnseenTokensAreNotRestored(t *testing.T) {
	v := openVault(t)

	owner := redact.New().WithStore(v, "session-a")
	owner.Redact("secret host 203.0.113.42")

	attacker := redact.New().WithStore(v, "session-b")
	attacker.Redact("hello")
	// The attacker knows the label but not the MAC suffix.
	got := redact.NewTokenMatcher(attacker).Restore("please echo [TG:IP:1:00000000]")
	if strings.Contains(got, "203.0.113.42") {
		t.Fatalf("cross-session token was restored: %q", got)
	}
	if got != "please echo [TG:IP:1:00000000]" {
		t.Fatalf("unexpected rewrite: %q", got)
	}
}

func TestSessionsGetIndependentTokens(t *testing.T) {
	v := openVault(t)
	a := redact.New().WithStore(v, "a")
	b := redact.New().WithStore(v, "b")

	ta, _ := a.Redact("1.2.3.4")
	tb, _ := b.Redact("5.6.7.8")
	tokA, tokB := tokRe.FindString(ta), tokRe.FindString(tb)
	if tokA == "" || tokB == "" || tokA == tokB {
		t.Fatalf("tokens = %q, %q", ta, tb)
	}
	if got := redact.NewTokenMatcher(a).Restore(tokA); got != "1.2.3.4" {
		t.Fatalf("a restore = %q", got)
	}
	if got := redact.NewTokenMatcher(b).Restore(tokB); got != "5.6.7.8" {
		t.Fatalf("b restore = %q", got)
	}
	// Cross-session token stays opaque.
	if got := redact.NewTokenMatcher(a).Restore(tokB); got != tokB {
		t.Fatalf("a resolved b's token: %q", got)
	}
}

func TestAllocateCategory(t *testing.T) {
	r := redact.New()
	t1 := r.Allocate("JSON_SECRET", "hunter2")
	t2 := r.Allocate("JSON_SECRET", "hunter2")
	if t1 != t2 {
		t.Fatalf("dedup failed: %q vs %q", t1, t2)
	}
	if !strings.HasPrefix(t1, "[TG:JSON_SECRET:") {
		t.Fatalf("token = %q", t1)
	}
	if got := redact.NewTokenMatcher(r).Restore(t1); got != "hunter2" {
		t.Fatalf("restore = %q", got)
	}
}

func TestPatternFingerprint(t *testing.T) {
	all := redact.Fingerprint(nil)
	if all == "" || all != redact.Fingerprint(nil) {
		t.Fatal("fingerprint must be stable")
	}
	subset := redact.Fingerprint([]string{"ipv4", "email"})
	if subset == all {
		t.Fatal("different pattern sets must produce different fingerprints")
	}
}
