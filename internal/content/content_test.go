package content_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/content"
	"github.com/qo-roj/tidegate/internal/redact"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want content.Kind
	}{
		{"json object", `{"a":1,"b":[1,2]}`, content.KindJSON},
		{"json array", `[{"a":1},{"a":2}]`, content.KindJSON},
		{"apache log", "10.0.0.1 - - [01/Oct/2026:15:07:51 +0200] \"GET / HTTP/1.1\" 200 12\n10.0.0.2 - - [01/Oct/2026:15:07:52 +0200] \"GET /x HTTP/1.1\" 404 0", content.KindLog},
		{"syslog", "Oct  1 15:07:51 host app[123]: started\nOct  1 15:07:52 host app[123]: ready", content.KindLog},
		{"diff", "--- a/x.go\n+++ b/x.go\n@@ -1,2 +1,2 @@\n-old\n+new", content.KindDiff},
		{"go code", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(1) }", content.KindCode},
		{"prose", "The tide came in and the shell decided what stays.", content.KindText},
		{"empty", "", content.KindText},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := content.Detect(tc.in); got != tc.want {
				t.Fatalf("Detect = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactJSONKeys(t *testing.T) {
	src := `{"user":"alice","password":"hunter2","nested":{"api_key":"sk-abc123","ok":true},"note":"keep me"}`

	var seen []string
	out, n := content.RedactJSONKeys(src, func(key, value string) string {
		seen = append(seen, key+"="+value)
		return "[TG:SECRET:1]"
	})
	if n != 2 {
		t.Fatalf("replaced %d values, want 2 (%v)", n, seen)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("output is not valid JSON: %s", out)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "sk-abc123") {
		t.Fatalf("secret leaked: %s", out)
	}
	if !strings.Contains(out, `"note": "keep me"`) && !strings.Contains(out, `"note":"keep me"`) {
		t.Fatalf("non-sensitive value was rewritten: %s", out)
	}
	if !strings.Contains(out, `"user":"alice"`) {
		t.Fatalf("user field was rewritten: %s", out)
	}
}

func TestRedactJSONKeysEscapedValue(t *testing.T) {
	src := `{"password":"pa\"ss\\word","other":"x"}`
	var got string
	out, n := content.RedactJSONKeys(src, func(key, value string) string {
		got = value
		return "[TG:SECRET:2]"
	})
	if n != 1 || got != `pa"ss\word` {
		t.Fatalf("n=%d value=%q", n, got)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
}

func TestRedactJSONKeysEscapingRoundTrip(t *testing.T) {
	cases := []string{
		`{"password":"line\nbreak","x":1}`,
		`{"password":"quote\"inside","x":1}`,
		`{"password":"back\\slash","x":1}`,
		`{"password":"caf\u00e9","x":1}`,
		`{"password":"emoji \ud83d\ude00","x":1}`,
	}
	for _, src := range cases {
		var stored string
		out, n := content.RedactJSONKeys(src, func(key, value string) string {
			stored = value
			return "[TG:SECRET:1]"
		})
		if n != 1 {
			t.Errorf("%s: replaced %d", src, n)
			continue
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("%s: invalid output %s", src, out)
		}
		// The stored original must be the decoded value, and re-encoding it
		// must reproduce a valid document.
		reencoded, err := json.Marshal(map[string]string{"password": stored})
		if err != nil || !json.Valid(reencoded) {
			t.Errorf("%s: stored %q does not round-trip: %v", src, stored, err)
		}
	}
}

func TestRedactJSONKeysSkipsTokensAndEmpty(t *testing.T) {
	src := `{"token":"[TG:SECRET:1]","secret":"","password":null}`
	out, n := content.RedactJSONKeys(src, func(key, value string) string { return "[TG:SECRET:9]" })
	if n != 0 || out != src {
		t.Fatalf("n=%d out=%s", n, out)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	yes := []string{"password", "PASSWORD", "api_key", "apiKey", "client-secret", "db_url", "DSN", "authorization", "set-cookie"}
	no := []string{"user", "hostname", "count", "public_key", "path"}
	for _, k := range yes {
		if !content.IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range no {
		if content.IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestShieldTimestamps(t *testing.T) {
	src := "10.0.0.1 - - [01/Oct/2026:15:07:51 +0200] \"GET / HTTP/1.1\" 200\n" +
		"2026-10-01T15:07:51.712345Z ERROR boom\n" +
		"trace at 15:07:51.712345 before failure"
	out, restore := content.ShieldTimestamps(src)

	if strings.Contains(out, "15:07:51") || strings.Contains(out, "01/Oct/2026") {
		t.Fatalf("timestamps not shielded: %q", out)
	}
	if got := restore(out); got != src {
		t.Fatalf("restore mismatch:\n got %q\nwant %q", got, src)
	}
}

func TestShieldKeepsJSONValid(t *testing.T) {
	src := `{"timestamp":"2026-10-01T15:07:51Z","host":"h"}`
	out, restore := content.ShieldTimestamps(src)
	if !json.Valid([]byte(out)) {
		t.Fatalf("shielded JSON invalid: %q", out)
	}
	if restore(out) != src {
		t.Fatal("restore mismatch")
	}
}

// TestShieldPreventsPhoneFalsePositive is the structural regression test for
// the v0.6.3 bug: the phone pattern read a log timestamp as a NANP number.
func TestShieldPreventsPhoneFalsePositive(t *testing.T) {
	line := "15:07:51.712345 2026 client denied by server configuration"
	shielded, restore := content.ShieldTimestamps(line)
	redacted, summary := redact.New().Redact(shielded)
	out := restore(redacted)

	if summary["phone"] != 0 {
		t.Fatalf("phone pattern fired on a timestamp: %v", summary)
	}
	if out != line {
		t.Fatalf("line changed: %q", out)
	}

	// A real phone number in the same line is still redacted.
	withPhone := "15:07:51.712345 call +1 712-345-2026 now"
	shielded, restore = content.ShieldTimestamps(withPhone)
	redacted, summary = redact.New().Redact(shielded)
	if summary["phone"] == 0 {
		t.Fatal("real phone number was not redacted")
	}
	if !strings.Contains(restore(redacted), "15:07:51.712345") {
		t.Fatalf("timestamp lost: %q", restore(redacted))
	}
}
