package route

import (
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/rules"
)

// Pattern toggles from [redaction.patterns] must reach the per-request
// Redactor. Regression test for the pre-fix behavior: RedactionFlags were
// parsed but never consulted — NewWithNames had no caller.
func TestPatternTogglesReachRedactor(t *testing.T) {
	cfg, err := rules.ParseConfigBytes([]byte(`
[redaction.patterns]
ipv4 = false
email = false
ssn_us = true
`), "user")
	if err != nil {
		t.Fatal(err)
	}
	rs := rules.BuildRuleSet(cfg, "user")
	r := New(rs, nil, nil)

	red := r.newRedactor()
	if red == nil {
		t.Fatal("newRedactor returned nil")
	}

	// IPv4 and email disabled by config: content must pass through.
	out, _ := red.Redact("server is 192.168.1.10 and mail goes to bob@example.com")
	if out != "server is 192.168.1.10 and mail goes to bob@example.com" {
		t.Errorf("disabled patterns still redacted: %q", out)
	}

	// SSN enabled by config: must still redact.
	out, _ = red.Redact("ssn 123-45-6789 here")
	if out == "ssn 123-45-6789 here" {
		t.Error("enabled pattern (ssn_us) did not redact")
	}
}

// A rule set with no toggle entries at all must behave like the old
// defaults (all default patterns on).
func TestNoTogglesDefaultBehavior(t *testing.T) {
	cfg, err := rules.ParseConfigBytes([]byte(`
[redact]
~/projects/**
`), "user")
	if err != nil {
		t.Fatal(err)
	}
	rs := rules.BuildRuleSet(cfg, "user")
	r := New(rs, nil, nil)

	red := r.newRedactor()
	out, _ := red.Redact("connect to 10.0.0.5 as bob@example.com")
	if out == "connect to 10.0.0.5 as bob@example.com" {
		t.Error("default patterns were not applied when no toggles configured")
	}
}

// Extended patterns (private IPs) must activate when a config enables them.
func TestExtendedPatternActivation(t *testing.T) {
	cfg, err := rules.ParseConfigBytes([]byte(`
[redaction.patterns]
ipv4_private = true
`), "user")
	if err != nil {
		t.Fatal(err)
	}
	rs := rules.BuildRuleSet(cfg, "user")
	r := New(rs, nil, nil)

	red := r.newRedactor()
	out, _ := red.Redact("proxy_pass http://10.0.0.5:8080")
	if out == "proxy_pass http://10.0.0.5:8080" {
		t.Error("ipv4_private toggle did not activate the extended pattern")
	}
}

// Structure-anchored patterns (syslog hostname, passwd username) must activate
// through the config toggle path — regression test for the 2026-09-03
// syslog/passwd hostname/username leaks.
func TestStructurePatternsActivateViaToggle(t *testing.T) {
	cfg, err := rules.ParseConfigBytes([]byte(`
[redaction.patterns]
syslog_hostname = true
passwd_username = true
`), "user")
	if err != nil {
		t.Fatal(err)
	}
	rs := rules.BuildRuleSet(cfg, "user")
	r := New(rs, nil, nil)
	red := r.newRedactor()

	out, _ := red.Redact("Sep  3 17:54:01 himbeerkuchen systemd[1]: Started apt.\n")
	if !strings.Contains(out, "Sep  3 17:54:01 [TG:HOST:1] systemd[1]") {
		t.Errorf("syslog_hostname toggle inactive: %q", out)
	}

	out, _ = red.Redact("sid:x:1000:1000:Sid:/home/sid:/usr/bin/fish\n")
	if !strings.HasPrefix(out, "[TG:USER:1]:x:1000:1000:") {
		t.Errorf("passwd_username toggle inactive: %q", out)
	}
}

// accesslog_hostname must activate through the config toggle path — the
// 2026-10-01 Earl report: vhost myhost.com survived while the client IP was
// tokenized, because no pattern covered the access-log vhost shape.
func TestAccesslogHostnameActivatesViaToggle(t *testing.T) {
	cfg, err := rules.ParseConfigBytes([]byte(`
[redaction.patterns]
accesslog_hostname = true
`), "user")
	if err != nil {
		t.Fatal(err)
	}
	rs := rules.BuildRuleSet(cfg, "user")
	r := New(rs, nil, nil)
	red := r.newRedactor()

	in := `myhost.com:443 203.0.113.7 - - [01/Oct/2026:14:44:22 +0200] "GET / HTTP/1.1" 404 512 "-" "curl"` + "\n"
	// Unmentioned code-default patterns stay enabled, so the client IP is
	// tokenized by ipv4 (which runs earlier). Both tokens in one line is
	// exactly the fixed behavior.
	out, _ := red.Redact(in)
	if !strings.HasPrefix(out, "[TG:HOST:1]:443 [TG:IP:1] - - [01/Oct/2026:14:44:22 +0200]") {
		t.Errorf("accesslog_hostname toggle inactive: %q", out)
	}
	if strings.Contains(out, "myhost.com") {
		t.Errorf("vhost survived: %q", out)
	}
}
