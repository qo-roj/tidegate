package redact

import (
	"regexp"
	"strings"
	"testing"
)

// newTestRedactor builds a Redactor with only the named patterns enabled.
func newTestRedactor(names ...string) *Redactor {
	r := New().WithPatterns(AllPatterns())
	for _, p := range r.patterns {
		p.Enabled = false
	}
	for _, p := range r.patterns {
		for _, n := range names {
			if p.Name == n {
				p.Enabled = true
			}
		}
	}
	return r
}

func TestSyslogHostnameRedacts(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	in := "Sep  3 17:54:01 himbeerkuchen systemd[1]: Started Daily apt download.\n"
	out, s := r.Redact(in)
	if !strings.Contains(out, "[TG:HOST:1] systemd[1]") {
		t.Errorf("hostname not redacted: %q", out)
	}
	if !strings.Contains(out, "Sep  3 17:54:01") {
		t.Errorf("timestamp was altered: %q", out)
	}
	if s["syslog_hostname"] != 1 {
		t.Errorf("summary = %v, want syslog_hostname: 1", s)
	}
}

func TestSyslogHostnameISOTimestamp(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, _ := r.Redact("2026-09-03T17:54:03.123456+02:00 rotten-berry sshd[4242]: Failed password\n")
	if !strings.Contains(out, "[TG:HOST:1] sshd[4242]") {
		t.Errorf("ISO-format hostname not redacted: %q", out)
	}
}

func TestSyslogHostnameDedup(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, s := r.Redact("Sep  3 17:54:01 host-a kernel: x\nSep  3 17:54:02 host-a kernel: y\nSep  3 17:54:03 host-b kernel: z\n")
	if got := strings.Count(out, "[TG:HOST:1]"); got != 2 {
		t.Errorf("same hostname should reuse token, got %d HOST:1 in %q", got, out)
	}
	if !strings.Contains(out, "[TG:HOST:2]") || strings.Count(out, "[TG:HOST:2]") != 1 {
		t.Errorf("second hostname should get HOST:2, got %q", out)
	}
	if s["syslog_hostname"] != 3 {
		t.Errorf("summary = %v, want 3", s)
	}
}

// Access-log vhost pattern: Apache/nginx combined logs with a leading
// virtual host (`vhost[:port] client - - [dd/Mon/yyyy:…]`) must tokenize
// only the vhost. Found live by Earl: myhost.com survived redaction while
// the client IP was tokenized (2026-10-01).
func TestAccesslogHostnameRedacts(t *testing.T) {
	r := newTestRedactor("accesslog_hostname")
	in := `myhost.com:443 203.0.113.7 - - [01/Oct/2026:14:44:22 +0200] "GET /en/?id=147&view=category HTTP/1.1" 404 32445 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"` + "\n"
	out, s := r.Redact(in)
	if !strings.HasPrefix(out, "[TG:HOST:1]:443 203.0.113.7 - - [01/Oct/2026:14:44:22 +0200]") {
		t.Errorf("vhost not redacted with structure intact: %q", out)
	}
	if strings.Contains(out, "myhost.com") {
		t.Errorf("hostname survived redaction: %q", out)
	}
	if s["accesslog_hostname"] != 1 {
		t.Errorf("summary = %v, want accesslog_hostname: 1", s)
	}
}

// The exact form Earl pasted: client already tokenized by the IP pattern,
// vhost still plaintext. The pattern must survive [TG:IP:N] in the client
// field and not re-tokenize the IP token.
func TestAccesslogHostnameAfterIPRedaction(t *testing.T) {
	r := newTestRedactor("accesslog_hostname")
	in := `myhost.com:443 [TG:IP:1] - - [01/Oct/2026:14:44:22 +0200] "GET / HTTP/1.1" 404 32445 "-" "Mozilla/5.0"` + "\n"
	out, _ := r.Redact(in)
	if !strings.HasPrefix(out, "[TG:HOST:1]:443 [TG:IP:1] - - [01/Oct/2026:14:44:22 +0200]") {
		t.Errorf("unexpected output: %q", out)
	}
	restored := r.Restore(out)
	if restored != in {
		t.Errorf("restore round-trip failed:\n got %q\nwant %q", restored, in)
	}
}

func TestAccesslogHostnameVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no port", "api.example.org 192.168.1.5 - - [30/Sep/2026:23:59:59 +0000] \"POST /login HTTP/2.0\" 401 87 \"-\" \"-\"",
			"[TG:HOST:1] 192.168.1.5 - - [30/Sep/2026:23:59:59 +0000]"},
		{"rfc3339", "cdn.mycorp.internal:8443 [TG:IP:2] - - [2026-09-30T23:59:59Z] \"GET / HTTP/1.1\" 200 10 \"-\" \"-\"",
			"[TG:HOST:1]:8443 [TG:IP:2] - - [2026-09-30T23:59:59Z]"},
		{"dash client", "shop.example.net:443 - - - [01/Oct/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"",
			"[TG:HOST:1]:443 - - - [01/Oct/2026:00:00:00 +0000]"},
		{"ip vhost", "10.0.0.5:443 203.0.113.9 - - [01/Oct/2026:14:44:22 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"",
			"[TG:HOST:1]:443 203.0.113.9 - - [01/Oct/2026:14:44:22 +0200]"},
	}
	for _, tc := range cases {
		// Fresh redactor per case: counters accumulate across Redact calls
		// on a shared Redactor, so token numbers would drift.
		r := newTestRedactor("accesslog_hostname")
		out, _ := r.Redact(tc.in + "\n")
		if !strings.HasPrefix(out, tc.want) {
			t.Errorf("%s: got %q, want prefix %q", tc.name, out, tc.want)
		}
	}
}

// Prose must pass through untouched: the pattern is structure-anchored, so
// a hostname in prose, a normal combined log without vhost, dated prose and
// mid-line occurrences all stay readable.
func TestAccesslogHostnameProseSafety(t *testing.T) {
	r := newTestRedactor("accesslog_hostname")
	cases := []string{
		"You can run it on myhost.com:443 - see our docs for details.",
		"203.0.113.7 - - [01/Oct/2026:14:44:22 +0200] \"GET / HTTP/1.1\" 200 512 \"-\" \"curl\" (no vhost)",
		"Check https://myhost.com:443 - - [careful] mid-line",
		"myhost.com is where the dash dash - - shape appears in prose [01/Oct/2026:14:44:22 +0200] but not at line start with a client field.",
		"2026-09-30 somehost - - [2026-09-30T10:00:00Z] dated prose lookalike",
	}
	for _, in := range cases {
		out, s := r.Redact(in + "\n")
		if out != in+"\n" {
			t.Errorf("prose modified: %q -> %q", in, out)
		}
		if len(s) != 0 {
			t.Errorf("prose produced redactions %v for %q", s, in)
		}
	}
}

// Same vhost across lines dedupes to one token; a second vhost gets its own.
func TestAccesslogHostnameDedup(t *testing.T) {
	r := newTestRedactor("accesslog_hostname")
	out, s := r.Redact("a.example.com:443 1.2.3.4 - - [01/Oct/2026:10:00:00 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"\n" +
		"a.example.com:443 1.2.3.4 - - [01/Oct/2026:10:00:01 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"\n" +
		"b.example.com:443 1.2.3.4 - - [01/Oct/2026:10:00:02 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"\n")
	if got := strings.Count(out, "[TG:HOST:1]"); got != 2 {
		t.Errorf("same vhost should reuse token, got %d HOST:1 in %q", got, out)
	}
	if strings.Count(out, "[TG:HOST:2]") != 1 {
		t.Errorf("second vhost should get HOST:2, got %q", out)
	}
	if s["accesslog_hostname"] != 3 {
		t.Errorf("summary = %v, want 3", s)
	}
}

// Ordering: with ipv4 also enabled, an IP-literal vhost is attributed to the
// IP pattern (which runs earlier and consumes the span), not to this pattern.
func TestAccesslogHostnameIPVhostAttribution(t *testing.T) {
	r := newTestRedactor("ipv4", "accesslog_hostname")
	out, s := r.Redact("10.0.0.5:443 203.0.113.9 - - [01/Oct/2026:14:44:22 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"-\"\n")
	if !strings.Contains(out, "[TG:IP:1]:443 [TG:IP:2] - - ") {
		t.Errorf("IP vhost not attributed to IP pattern: %q", out)
	}
	if strings.Contains(out, "[TG:HOST:") {
		t.Errorf("vhost pattern stole an IP-literal vhost: %q", out)
	}
	if s["accesslog_hostname"] != 0 {
		t.Errorf("summary = %v, want no accesslog_hostname", s)
	}
}

func TestSyslogHostnameIgnoresMidLineTimestamps(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	out, s := r.Redact("The meeting notes say 17:54:01 himbeerkuchen and nothing else.")
	if out != "The meeting notes say 17:54:01 himbeerkuchen and nothing else." {
		t.Errorf("mid-line timestamp falsely matched: %q", out)
	}
	if len(s) != 0 {
		t.Errorf("unexpected redactions: %v", s)
	}
}

// Regression 2026-09-07 review: dated prose at line start ("Jan 15 09:30:00
// all hands on deck") matched the old timestamp+word shape and redacted the
// first word as a hostname. The pattern now requires the syslog process tag
// (`word…[pid]:`) that every real log line carries.
func TestSyslogHostnameIgnoresDatedProse(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	cases := []string{
		"Jan 15 09:30:00 all hands on deck at headquarters",
		"Jun  1 08:00:00 we deploy then run tests",
		"Dec 31 23:59:59 happy new year everyone",
		"2026-09-07T12:30:45Z everyone remembers this day fondly",
		"Sep  3 17:54:01 no tag means no log line here",
	}
	for _, c := range cases {
		out, s := r.Redact(c)
		if out != c {
			t.Errorf("dated prose falsely matched: %q → %q", c, out)
		}
		if len(s) != 0 {
			t.Errorf("false-positive summary on %q: %v", c, s)
		}
	}
}

// Kernel-style lines (no pid) and RFC5424-ish lines must still redact the
// hostname after the process-tag requirement was added.
func TestSyslogHostnameKernelAndTaglessProcess(t *testing.T) {
	cases := []string{
		"Sep  3 17:54:01 himbeerkuchen kernel: nf_conntrack: table full",
		"Sep  3 17:54:01 himbeerkuchen systemd[1]: Started Daily apt.",
		"2026-09-03T17:54:03.123456+02:00 rotten-berry sshd[4242]: Failed password",
	}
	for _, c := range cases {
		r := newTestRedactor("syslog_hostname") // fresh: each case expects HOST:1
		out, s := r.Redact(c)
		if !strings.Contains(out, "[TG:HOST:1]") {
			t.Errorf("real syslog line not redacted: %q → %q", c, out)
		}
		if s["syslog_hostname"] != 1 {
			t.Errorf("summary = %v, want syslog_hostname: 1 for %q", s, c)
		}
	}
}

func TestPasswdUsernameRedacts(t *testing.T) {
	r := newTestRedactor("passwd_username")
	in := "root:x:0:0:root:/root:/bin/bash\nsid:x:1000:1000:Sid Crab:/home/sid:/usr/bin/fish\n"
	out, s := r.Redact(in)
	if !strings.HasPrefix(out, "[TG:USER:1]:x:0:0:") {
		t.Errorf("first username not redacted: %q", out)
	}
	if !strings.Contains(out, "[TG:USER:2]:x:1000:1000:Sid Crab:/home/sid") {
		t.Errorf("second username not redacted: %q", out)
	}
	if s["passwd_username"] != 2 {
		t.Errorf("summary = %v, want 2", s)
	}
}

func TestPasswdUsernameIgnoresColonPairs(t *testing.T) {
	r := newTestRedactor("passwd_username")
	cases := []string{
		"user:password is a common example phrase",
		"username: admin",
		"localhost: 127.0.0.1",
		`"json_key": {"nested": 1}`,
		"# comment: explaining something",
		"time: 12:30 and time: 09:15",
		// Regression 2026-09-07 review: four-field colon-numeric prose
		// matched the old {1,128} password field. The field now accepts
		// only real passwd/shadow values (x, !/!!/*, $hash, empty).
		"video:1920:1080:60",
		"settings:default:100:200",
		"time:12:30:45 and the meeting started",
		"crop:320:240:16",
	}
	for _, c := range cases {
		out, s := r.Redact(c)
		if out != c {
			t.Errorf("false positive on %q → %q", c, out)
		}
		if len(s) != 0 {
			t.Errorf("false-positive summary on %q: %v", c, s)
		}
	}
}

// Real passwd/shadow field shapes must all still redact: the x placeholder,
// locked (! / !!), disabled (*), $-hashes, and passwordless (empty) fields.
func TestPasswdUsernameShadowVariants(t *testing.T) {
	r := newTestRedactor("passwd_username")
	cases := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"lockeduser:!:19000:0:99999:7:::",
		"lockeduser2:!!:19000:0:99999:7:::",
		"daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"sid:$6$rounds=656000$abc123$hashhash:19998:0:99999:7:::",
		"nopass::1000:1000::/home/n:/bin/sh",
	}
	for _, c := range cases {
		out, s := r.Redact(c)
		if !strings.HasPrefix(out, "[TG:USER:") {
			t.Errorf("shadow-style line not redacted: %q → %q", c, out)
		}
		if s["passwd_username"] != 1 {
			t.Errorf("summary = %v, want passwd_username: 1 for %q", s, c)
		}
	}
}

// Group-span patterns must keep the anchoring context (timestamp) while the
// redacted value round-trips through Restore.
func TestGroupPatternRestoreRoundTrip(t *testing.T) {
	r := newTestRedactor("syslog_hostname")
	in := "Sep  3 17:54:01 himbeerkuchen systemd[1]: Started\n"
	red, _ := r.Redact(in)
	restored := r.Restore(red)
	if restored != in {
		t.Errorf("round-trip mismatch:\nred:  %q\nwant: %q", restored, in)
	}
}

// Group indices that don't exist in a match must leave content untouched.
func TestGroupSpanMissingGroup(t *testing.T) {
	r := New()
	r.WithPatterns([]*Pattern{{
		Name:     "bogus_group",
		Regex:    regexp.MustCompile(`^(\w+) world`),
		Category: "TEST",
		Group:    5, // no such group
	}})
	out, s := r.Redact("hello world")
	if out != "hello world" {
		t.Errorf("out-of-range group redacted anyway: %q", out)
	}
	if len(s) != 0 {
		t.Errorf("unexpected summary: %v", s)
	}
}

// Phone covers international form (+ prefix) and the bare NANP form — a
// plain "555-123-4567" previously passed through despite the "or 10+ digits"
// comment. Bare 10-digit strings are covered deliberately: for a redaction
// tool a missed number is worse than a flagged order-ID. \b keeps it from
// matching inside longer digit runs.
func TestPhoneCoversNANPForm(t *testing.T) {
	r := newTestRedactor("phone")
	cases := []string{
		"call 555-123-4567 now",
		"call 5551234567 now",
		"call (555) 123-4567 now",
		"call +1 (555) 123-4567 now",
		"call +49 170 1234567 now",
	}
	for _, c := range cases {
		r := newTestRedactor("phone") // fresh: each case expects PHONE:1
		out, s := r.Redact(c)
		if !strings.Contains(out, "[TG:PHONE:1]") {
			t.Errorf("phone not redacted: %q → %q", c, out)
		}
		if s["phone"] != 1 {
			t.Errorf("summary = %v, want phone: 1 for %q", s, c)
		}
	}
	// Not phones: longer digit runs, dates, IPs — must not match the 3-3-4
	// shape. A bare 10-digit string is indistinguishable from a NANP
	// number, so order IDs DO match — accepted over-redaction (fail-safe
	// direction; tokens restore in responses).
	for _, c := range []string{
		"order 12345678901 done",
		"on 2026-09-07 at 12:30",
		"ip 10.1.2.3 end",
	} {
		out, s := r.Redact(c)
		if out != c || len(s) != 0 {
			t.Errorf("false positive: %q → %q (%v)", c, out, s)
		}
	}
	if out, _ := r.Redact("order 1234567890 done"); !strings.Contains(out, "[TG:PHONE:1]") {
		t.Errorf("bare 10-digit should match NANP shape (documented trade-off): %q", out)
	}
}

// ipv4_private must run before ipv4 (evaluation order in patternNames) so the
// private-range toggle is meaningful: with both enabled, RFC1918 addresses
// are attributed to ipv4_private; public ones to ipv4.
func TestIPv4PrivateOrdering(t *testing.T) {
	r := newTestRedactor("ipv4_private", "ipv4")
	out, s := r.Redact("10.1.2.3 and 172.20.1.5 and 8.8.8.8")
	if !strings.Contains(out, "[TG:IP:") {
		t.Errorf("addresses not redacted: %q", out)
	}
	if s["ipv4_private"] != 2 {
		t.Errorf("ipv4_private = %d, want 2 (10.x and 172.16-31.x)", s["ipv4_private"])
	}
	if s["ipv4"] != 1 {
		t.Errorf("ipv4 = %d, want 1 (public 8.8.8.8)", s["ipv4"])
	}
}
