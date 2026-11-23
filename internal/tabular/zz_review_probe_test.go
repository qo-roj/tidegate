package tabular

import (
	"regexp"
	"testing"
)

var reUUIDOut = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)

// TestGeneralizeUUIDShape: a reviewer round caught generalized UUIDs emitted
// as 8-4-3-3-12 (3-char version/variant groups) — downstream UUID parsers
// reject that shape. Output must be a well-formed v4 UUID per RFC 4122.
func TestGeneralizeUUIDShape(t *testing.T) {
	src := "id,user\n550e8400-e29b-41d4-a716-446655440000,alice\n6fa459ea-ee8a-3ca4-894e-db77e160355e,bob\n3f2504e0-4f89-11d3-9a0c-0305e82c3301,carol\n"
	res := Generalize(src, Options{Salt: "test-salt"})
	if !res.Applied {
		t.Fatalf("table not applied:\n%s", res.Source)
	}
	found := 0
	for _, m := range reUUIDOut.FindAllString(res.Source, -1) {
		_ = m
		found++
	}
	if found != 3 {
		t.Fatalf("expected 3 generalized v4-shaped UUIDs, got %d:\n%s", found, res.Source)
	}
	// original UUIDs must not survive
	for _, orig := range []string{"550e8400-e29b-41d4-a716-446655440000", "6fa459ea-ee8a-3ca4-894e-db77e160355e", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"} {
		if want := orig; contains(res.Source, want) {
			t.Fatalf("original UUID %s survived generalization:\n%s", orig, res.Source)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
