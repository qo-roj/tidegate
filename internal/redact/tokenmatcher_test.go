package redact

import (
	"strings"
	"testing"
)

func TestTokenMatcherExactMatch(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("Server at 203.0.113.42 and admin@example.com")
	tm := NewTokenMatcher(r)

	content := "Check [TG:IP:1:00000000] and contact [TG:EMAIL:1:00000000]"
	restored := tm.Restore(content)

	if !strings.Contains(restored, "203.0.113.42") {
		t.Error("expected IP to be restored")
	}
	if !strings.Contains(restored, "admin@example.com") {
		t.Error("expected email to be restored")
	}
}

func TestTokenMatcherFuzzyMatch(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)

	tests := []string{
		`"TG:IP:1:00000000"`, // quotes
		"`TG:IP:1:00000000`", // backticks
		`TG:IP:1:00000000`,   // no brackets
		`TG_IP_1_00000000`,   // underscores
	}

	for _, fuzzy := range tests {
		restored := tm.Restore(fuzzy)
		if !strings.Contains(restored, "203.0.113.42") {
			t.Errorf("fuzzy match %q → %q, expected IP restored", fuzzy, restored)
		}
	}
}

func TestTokenMatcherUnresolvedToken(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)

	// Token that doesn't exist in the mapping
	content := "Unknown [TG:IP:99:00000000] here"
	restored := tm.Restore(content)

	if !strings.Contains(restored, "[TG:IP:99:00000000]") {
		t.Error("unresolved token should be left as-is")
	}
}

func TestTokenMatcherUnresolvedTokensList(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)

	content := "Known [TG:IP:1:00000000] and unknown [TG:IP:42:00000000] and also [TG:EMAIL:3:00000000]"
	unresolved := tm.UnresolvedTokens(content)

	if len(unresolved) != 2 {
		t.Errorf("expected 2 unresolved tokens, got %d", len(unresolved))
	}
}

func TestStreamRedactorBasic(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// Single chunk with complete token
	out := sr.ProcessChunk([]byte("The IP is [TG:IP:1:00000000] yes"))
	if !strings.Contains(string(out), "203.0.113.42") {
		t.Errorf("expected IP restored, got %q", out)
	}
}

func TestStreamRedactorSplitToken(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// Token split across two chunks
	out1 := sr.ProcessChunk([]byte("The IP is [TG:IP:"))
	if strings.Contains(string(out1), "203.0.113.42") {
		t.Error("should not have restored yet — token is incomplete")
	}

	out2 := sr.ProcessChunk([]byte("1:00000000] confirmed"))
	combined := string(out1) + string(out2)
	if !strings.Contains(combined, "203.0.113.42") {
		t.Errorf("expected IP restored after second chunk, got %q", combined)
	}
}

func TestStreamRedactorNoMappings(t *testing.T) {
	r := New()
	defer r.Clear()

	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// No mappings — should pass through unchanged
	out := sr.ProcessChunk([]byte("hello world"))
	if string(out) != "hello world" {
		t.Errorf("expected passthrough, got %q", out)
	}
}

func TestStreamRedactorFlush(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// Send a chunk that leaves a partial token in the buffer
	sr.ProcessChunk([]byte("IP is [TG:IP:"))
	remaining := sr.Flush()
	if len(remaining) == 0 {
		t.Error("expected remaining buffer to be flushed")
	}
}

func TestStreamRedactorMultipleTokens(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "IP 203.0.113.42 email admin@example.com token ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
	r.Redact(content)
	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// All three tokens in one chunk
	out := sr.ProcessChunk([]byte("Found [TG:IP:1:00000000] [TG:EMAIL:1:00000000] [TG:TOKEN:1:00000000] done"))
	outStr := string(out)

	if !strings.Contains(outStr, "203.0.113.42") {
		t.Error("expected IP restored")
	}
	if !strings.Contains(outStr, "admin@example.com") {
		t.Error("expected email restored")
	}
	if !strings.Contains(outStr, "ghp_") {
		t.Error("expected token restored")
	}
}

func TestStreamRedactorNoFalseBuffer(t *testing.T) {
	r := New()
	defer r.Clear()

	r.Redact("IP 203.0.113.42")
	tm := NewTokenMatcher(r)
	sr := NewStreamRedactor(tm)

	// Text that ends with [ but is not a token
	out1 := sr.ProcessChunk([]byte("array[0] = [TG:IP:1:00000000]"))
	out2 := sr.ProcessChunk([]byte(" value[1]"))
	combined := string(out1) + string(out2)

	if !strings.Contains(combined, "203.0.113.42") {
		t.Error("expected IP restored")
	}
	if !strings.Contains(combined, "array[0]") {
		t.Error("expected array[0] to be preserved")
	}
}

func TestSanitizeForLog(t *testing.T) {
	s := "Redacted [TG:IP:1:00000000] with [TG:EMAIL:2:00000000]"
	result := SanitizeForLog(s)
	// Should keep tokens as-is (they don't contain original values)
	if result != s {
		t.Errorf("expected no change, got %q", result)
	}
}

func TestIsTokenContent(t *testing.T) {
	if !IsTokenContent("has [TG:IP:1:00000000] token") {
		t.Error("expected true for content with token")
	}
	if IsTokenContent("no tokens here") {
		t.Error("expected false for content without tokens")
	}
}

// TestRestoreExpandsNestedTokens covers proxy/stream restore: a mapping value
// that embeds another token must expand both, not strand the inner one.
func TestRestoreExpandsNestedTokens(t *testing.T) {
	tm := NewTokenMatcherFromMap(map[string]string{
		"[TG:DBURL:1:aaaaaaaa]":    "postgres://admin:[TG:PASSWORD:1:bbbbbbbb]@db:5432/app",
		"[TG:PASSWORD:1:bbbbbbbb]": "hunter2",
	})
	got := tm.Restore("connect [TG:DBURL:1:aaaaaaaa] now")
	want := "connect postgres://admin:hunter2@db:5432/app now"
	if got != want {
		t.Fatalf("restore = %q, want %q", got, want)
	}
}
