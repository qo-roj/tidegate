package redact

import (
	"strings"
	"testing"
)

// ProbeReviewerURLUserinfo: a dual-model reviewer claims credentials in URL
// userinfo for schemes outside the DSN list survive all default patterns —
// database_connection only lists DB schemes, and the email pattern cannot
// match a local part containing ':'. If the claim is real, the userinfo
// reaches the output verbatim.
func TestProbeReviewerURLUserinfo(t *testing.T) {
	for _, in := range []string{
		`curl https://alice:p@ss:word@example.com/path`,
		`ftp://admin:secret@host.example.net/file`,
		`connect to redis://svc:hunter2@cache.internal:6379/0 please`,
	} {
		for name, r := range map[string]*Redactor{
			"library-defaults": New(),
			"gateway-names":    NewWithNames(patternNames),
		} {
			out, _ := r.Redact(in)
			t.Logf("%s / %s -> %s", name, in, out)
			low := strings.ToLower(out)
			if strings.Contains(low, "p@ss:word@") {
				t.Errorf("%s: userinfo credential p@ss:word survived: %s", name, out)
			}
			if strings.Contains(low, "admin:secret@") {
				t.Errorf("%s: userinfo credential admin:secret survived: %s", name, out)
			}
			if strings.Contains(low, "svc:hunter2@") {
				t.Errorf("%s: userinfo credential svc:hunter2 survived: %s", name, out)
			}
		}
	}
}
