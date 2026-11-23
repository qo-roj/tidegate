package content

import (
	"encoding/json"
	"strings"
	"testing"
)

func redactAllKeys(key, value string) string {
	return "[TG:REDACTED]"
}

// ProbeReviewerEscapedQuote runs the exact payload a dual-model reviewer
// claimed bypasses key redaction: an object-valued sensitive key whose
// nested string contains an escaped quote. If the scanner is correct the
// password key IS redacted; if the claim is real, it survives verbatim.
func TestProbeReviewerEscapedQuote(t *testing.T) {
	payload := `{"password": {"note": "a\"b", "secret": "hunter2"}}`
	out, n := RedactJSONKeys(payload, redactAllKeys)
	t.Logf("redacted %d keys; output: %s", n, out)
	if strings.Contains(out, `{"note": "a\"b", "secret": "hunter2"}`) {
		t.Fatalf("REVIEWER CLAIM CONFIRMED: nested value under sensitive key survived unredacted: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("nested secret hunter2 survived unredacted: %s", out)
	}
}

// ProbeReviewerPlainControl: the same shape without the escaped quote, as a
// control — must redact in both engines.
func TestProbeReviewerPlainControl(t *testing.T) {
	payload := `{"password": {"note": "ab", "secret": "hunter2"}}`
	out, n := RedactJSONKeys(payload, redactAllKeys)
	if n == 0 || strings.Contains(out, "hunter2") {
		t.Fatalf("control failed: %d keys, nested secret survived: %s", n, out)
	}
}

// ProbeReviewerMinimalOverlapPanic is the minimal reproducer for the panic the
// escaped-quote probe exposed: a sensitive key nested in another sensitive
// key's object value. The outer rewrite consumed the span; the nested match
// must be skipped, not sliced with stale indices.
func TestProbeReviewerMinimalOverlapPanic(t *testing.T) {
	payload := `{"password": {"secret": "hunter2"}}`
	out, n := RedactJSONKeys(payload, redactAllKeys)
	t.Logf("redacted %d keys; output: %s", n, out)
	if strings.Contains(out, "hunter2") {
		t.Fatalf("nested secret survived: %s", out)
	}
	if !strings.Contains(out, "[TG:REDACTED]") {
		t.Fatalf("outer key not redacted: %s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("output is not valid JSON: %s", out)
	}
}

// ProbeReviewerDeepNesting: three levels of sensitive nesting — every level
// must be skipped-or-redacted without panicking, output stays valid JSON.
func TestProbeReviewerDeepNesting(t *testing.T) {
	payload := `{"password": {"token": {"api_key": "sk-live-abcdef"}}}`
	out, _ := RedactJSONKeys(payload, redactAllKeys)
	t.Logf("output: %s", out)
	if strings.Contains(out, "sk-live-abcdef") {
		t.Fatalf("deep nested secret survived: %s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("output is not valid JSON: %s", out)
	}
}
