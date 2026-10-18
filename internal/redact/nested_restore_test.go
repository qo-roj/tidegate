package redact

import (
	"strings"
	"testing"
)

// Nested-token regression: when one pattern's match embeds another token
// (email inside a database_connection URL, redacted by the earlier-running
// email pattern), Restore must expand the inner token too. Pre-fix, the
// DBURL value stored "postgres://admin:[TG:EMAIL:1:00000000]@..." and restore
// stranded the inner token. Found via dry-run --restore round-trip.
func TestRestoreNestedTokens(t *testing.T) {
	r := New()
	defer r.Clear()

	// email pattern runs before database_connection in DefaultPatterns,
	// reproducing the natural nesting.
	in := "db: postgres://admin:SuperSecret123@db.internal.lan:5432/prod"
	after, _ := r.Redact(in)
	if after != "db: [TG:DBURL:1:00000000]" {
		t.Fatalf("unexpected redaction: %q", after)
	}

	restored := r.Restore(after)
	if restored != in {
		t.Errorf("nested tokens not expanded:\n got %q\nwant %q", restored, in)
	}
}

// Restore must be deterministic when two tokens have equal length — the
// old sort had no tiebreak, so iteration order (random per map) decided.
func TestRestoreDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		r := New()
		// DBURL:1 and EMAIL:1 have identical token lengths; ensure the
		// nested value always fully expands on the first try.
		in := "mail bob@corp.example and db postgres://x:y@db.internal.lan:5432/p"
		after, _ := r.Redact(in)
		if r.Restore(after) != in {
			out := r.Restore(after)
			t.Fatalf("iteration %d: non-deterministic restore:\n in  %q\n out %q", i, in, out)
		}
		r.Clear()
	}
}

// A redacted value that legitimately contains token-shaped text must not
// expand — only actual mapping entries expand, and unknown tokens strand
// by design (UnresolvedTokens reports them).
func TestRestoreLeavesUnknownTokens(t *testing.T) {
	r := New()
	defer r.Clear()

	in := "quota [TG:IP:99:00000000] mentioned in a report"
	_, _ = r.Redact("server 10.1.2.3") // populate the mapping with a real token
	restored := r.Restore(in)
	if !strings.Contains(restored, "[TG:IP:99:00000000]") {
		t.Errorf("unknown token should strand as-is, got %q", restored)
	}
}
