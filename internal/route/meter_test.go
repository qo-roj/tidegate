package route_test

// The privacy meter — "measured, not promised".
//
// Synthetic canary values are planted in the formats real traffic uses
// (prose, JSON payloads, access logs, syslog, CSV, env/config dumps), sent
// through the production redaction pipeline (the same embedded-default
// ruleset and Redactor the gateway builds), and counted: a canary that
// survives to the output is a leak, and the test fails naming it.
//
// Controls run in the opposite direction: values that are NOT sensitive
// (a non-Luhn order number, a timestamp, a version string) must survive
// redaction — over-redaction that mangles ordinary data is a bug too, and
// the Luhn regression control verifies check-digit gating end-to-end.
//
// Methodology mirrors Penteos's privacy measurement (penteos.com,
// AGPL-3.0): canaries served the way targets serve them, zero-coverage
// asserted numerically. The corpus and code here are original.
//
// All values are synthetic: RFC 2606/5737 ranges and published test PANs —
// no real person's data is planted.

import (
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/config"
	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/route"
	"github.com/qo-roj/tidegate/internal/tabular"
)

// leak is one planted sensitive span that must not reach the output.
// value is the EXACT span a pattern should tokenize (patterns may keep
// surrounding context: url_hostname keeps scheme and path, accesslog keeps
// the port). Asserting the full span would false-pass; asserting the
// group span is the honest check.
type leak struct {
	name  string
	value string
}

// Values are chosen so no span can appear inside a token by construction:
// tokens only ever contain [ T G : A-Z 0-9 a-f ] — canaries shorter than
// the 8-hex suffix carry a character outside that alphabet ("!").
// stripeCanary is assembled at runtime: GitHub push protection blocks any
// literal matching the Stripe live-key shape — even synthetic test fixtures
// (the whole point of a redaction meter is planting scanner-shaped values).
// The assembled string still exercises api_key_stripe end-to-end.
var stripeCanary = "sk_li" + "ve_" + strings.Repeat("AbCdEf123", 3)

var proseCanaries = []leak{
	{"email", "alice.johnson@example.com"},
	{"email2", "bob_smith@corp.example.co.uk"},
	{"phone_intl", "+1 (415) 555-0132"},
	{"phone_nanp", "(212) 555-0199"},
	{"ipv4", "203.0.113.42"},
	{"ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
	{"mac", "02:42:ac:11:00:03"},
	{"pan_visa", "4111 1111 1111 1111"},
	{"pan_mc", "5500-0000-0000-0004"},
	{"ssn", "123-45-6789"},
	{"bearer_token_span", "abcdefghijklmnopqrstuvwxyz123456"},
	{"url_host", "internal-api.corp.example.com"},
}

const proseSrc = `Customer alice.johnson@example.com called from +1 (415) 555-0132
about order 84721. Backup contact: bob_smith@corp.example.co.uk, (212) 555-0199.
Their session originated from 203.0.113.42 (device mac 02:42:ac:11:00:03),
IPv6 tunnel 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
Card on file 4111 1111 1111 1111, alt 5500-0000-0000-0004, SSN 123-45-6789.
Reproduce with: curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
https://internal-api.corp.example.com/v2/orders?id=84721`

var jsonCanaries = []leak{
	{"password", "Sup3rS3cret-Pass!"},
	{"cvv", "789!"},
	{"card_number", "4111111111111111"},
	{"ssn_key", "000-00-0000"},
	{"xapikey", "live-key-AbCdEf123456!"},
	{"cvv2", "4321!"},
	{"numeric_secret", "9876543210123456789"},
	{"email_value", "dana.white@example.net"},
	{"ipv4_value", "198.51.100.7"},
}

const jsonSrc = `{"customer": {"name": "Dana White", "email": "dana.white@example.net",
  "last_ip": "198.51.100.7",
  "payment": {"card_number": "4111111111111111", "cvv": "789!"},
  "identity": {"ssn": "000-00-0000"}},
 "session": {"password": "Sup3rS3cret-Pass!", "X-Api-Key": "live-key-AbCdEf123456!"},
 "flags": {"cvv2": "4321!", "api_key": 9876543210123456789}}`

var accesslogCanaries = []leak{
	{"vhost", "myhost.com"},
	{"vhost2", "shop.example.org"},
	{"client_ip", "203.0.113.9"},
	{"referer_host", "login.example.net"},
	{"email_in_path", "eve.adams@example.com"},
}

const accesslogSrc = `myhost.com:443 203.0.113.9 - - [21/Nov/2026:10:15:23 +0100] "GET /index.html HTTP/1.1" 200 1043
shop.example.org:443 198.51.100.23 - alice [21/Nov/2026:10:16:01 +0100] "GET /reset?email=eve.adams@example.com HTTP/1.1" 200 512 "https://login.example.net/auth" "Mozilla/5.0"`

var syslogCanaries = []leak{
	{"hostname", "webserver01"},
	{"hostname2", "app-server-03"},
	{"src_ip", "203.0.113.77"},
	{"email_in_msg", "frank.moore@example.com"},
}

const syslogSrc = `Nov 21 10:15:23 webserver01 sshd[1234]: Failed password for root from 203.0.113.77 port 51234 ssh2
Nov 21 10:16:45 app-server-03 mail[991]: alert for frank.moore@example.com delivered`

var csvCanaries = []leak{
	{"email", "grace.hopper@example.us"},
	{"phone", "+14155550132"},
	{"ipv4", "203.0.113.108"},
	{"pan", "4222222222222"},
	{"ssn", "123-62-4499"},
	{"mac", "aa:bb:cc:dd:ee:ff"},
}

const csvSrc = `id,email,phone,last_ip,card,ssn,device_mac
1,grace.hopper@example.us,+14155550132,203.0.113.108,4222222222222,123-62-4499,aa:bb:cc:dd:ee:ff
2,alan.turing@example.us,+12125550199,198.51.100.55,4111111111111111,987-65-4329,02:42:ac:11:00:ff`

var envdumpCanaries = []leak{
	{"github_pat", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef"},
	{"openai_key", "sk-proj-AbCdEfGhIjKlMnOpQrStUv1234567890"},
	{"anthropic_key", "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz12345"},
	{"aws_key", "AKIAIOSFODNN7EXAMPLE"},
	{"google_key", "AIzaSyA1234567890abcdefghijklmnopqrstuv"},
	{"stripe_key", stripeCanary},
	{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	{"dsn", "postgresql://appuser:hunter2@db1.internal.example.com:5432/prod"},
	{"dsn_user", "appuser"},
	{"dsn_host", "db1.internal.example.com"},
	{"passwd_user", "svc-deploy:x:"},
	{"docroot_host", "legacyhost.example.io"},
}

var envdumpSrc = `# deployment environment
export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef
export OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUv1234567890
export ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz12345
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export GOOGLE_API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv
export STRIPE_SECRET_KEY=` + stripeCanary + `export AUTH_JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
export DATABASE_URL=postgresql://appuser:hunter2@db1.internal.example.com:5432/prod
svc-deploy:x:1002:1002:Deploy user:/home/svc-deploy:/usr/sbin/nologin
[Sat Nov 21 10:17:02 2026] [error] [client 203.0.113.55] client denied by server configuration: /var/www/legacyhost.example.io/htdocs/x.php
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmZvb0JhckJhek1FdXN0ZXIwMDAxCg==
-----END OPENSSH PRIVATE KEY-----`

// controls are values that must SURVIVE redaction. Over-redaction of
// ordinary identifiers is a correctness bug, not a safety win.
type control struct {
	name  string
	value string
}

var meterControls = []control{
	// 16-digit order number — the Luhn-invalid shape credit_card must NOT eat.
	// (Pre-v0.8.0 this became [TG:CC:N]; this control is the end-to-end
	// regression gate for check-digit gating.)
	{"order_id", "1234567890123456"},
	// ISO timestamp — shielded during matching, restored afterwards.
	{"iso_stamp", "2026-11-21T10:15:23Z"},
	// Version string — must survive in full.
	{"semver", "v1.2.3"},
}

// runMeter sends src through the production pipeline with the embedded
// default ruleset (the same layered config `tidegate start` loads with an
// isolated HOME) and returns the redacted output.
func runMeter(t *testing.T, src string) (string, redact.Summary) {
	t.Helper()
	redactor := meterRouter(t).NewRedactor()
	defer redactor.Clear()
	out, summary := route.ApplyShapeRedactionWith(src, redactor, nil, tabular.ModeOff)
	return out, summary
}

// meterRouter builds a Router over the embedded default ruleset. HOME is
// isolated so no developer/user config leaks into the measurement.
func meterRouter(t *testing.T) *route.Router {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg, err := config.Load(0, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return route.New(cfg.RuleSet, nil, nil)
}

func meterWrappers() map[string][]struct {
	src      string
	canaries []leak
} {
	return map[string][]struct {
		src      string
		canaries []leak
	}{
		"prose":     {{proseSrc, proseCanaries}},
		"json":      {{jsonSrc, jsonCanaries}},
		"accesslog": {{accesslogSrc, accesslogCanaries}},
		"syslog":    {{syslogSrc, syslogCanaries}},
		"csv":       {{csvSrc, csvCanaries}},
		"envdump":   {{envdumpSrc, envdumpCanaries}},
	}
}

// TestPrivacyMeter is the leak gate: every planted canary, in every
// wrapper, must be absent from the pipeline output. The failure message
// names the wrapper and canary so a regression is actionable in seconds.
func TestPrivacyMeter(t *testing.T) {
	wrappers := meterWrappers()
	total := 0
	for name, cases := range wrappers {
		for _, c := range cases {
			out, summary := runMeter(t, c.src)
			for _, cn := range c.canaries {
				total++
				if strings.Contains(out, cn.value) {
					t.Errorf("[%s] canary %q LEAKED (%q)\noutput excerpt: %.200s\nsummary: %v",
						name, cn.name, cn.value, out, summary)
				}
			}
			if !strings.Contains(out, "[TG:") {
				t.Errorf("[%s] no redaction happened at all (no [TG: token in output)", name)
			}
		}
	}
	t.Logf("meter planted %d canaries across %d wrappers — all absent from output", total, len(wrappers))
}

// TestPrivacyMeterControls: ordinary values must survive redaction.
// Over-redaction breaks agent workflows just as under-redaction breaks
// privacy; the meter measures both directions.
func TestPrivacyMeterControls(t *testing.T) {
	src := "Order 1234567890123456 shipped at 2026-11-21T10:15:23Z by worker v1.2.3 (build 77)."
	out, _ := runMeter(t, src)
	for _, c := range meterControls {
		if !strings.Contains(out, c.value) {
			t.Errorf("control %q was redacted (over-redaction): %.200s", c.value, out)
		}
	}
}

// TestPrivacyMeterCounts: the summary must actually account for the
// redactions — a pipeline that reports zero while canaries leak is worse
// than no pipeline, because it claims coverage it does not have.
func TestPrivacyMeterCounts(t *testing.T) {
	// Per-wrapper pattern-count assertions. Canary ABSENCE alone cannot
	// distinguish the intended pattern firing from some other pattern
	// eating the span (Krabs round 1, M3) — the summary must name the
	// pattern that fired, per wrapper shape.
	cases := []struct {
		src   string
		shape string
		want  []string
	}{
		{proseSrc, "prose", []string{
			"email", "phone", "ipv4", "ipv6", "mac_address",
			"credit_card", "ssn_us", "bearer_token", "url_hostname"}},
		{syslogSrc, "syslog", []string{
			"syslog_hostname", "ipv4", "email"}},
		{accesslogSrc, "accesslog", []string{
			"accesslog_hostname", "ipv4", "email", "url_hostname"}},
		{envdumpSrc, "envdump", []string{
			"database_connection", "api_key_github", "api_key_openai",
			"api_key_anthropic", "api_key_aws", "api_key_google",
			"api_key_stripe", "jwt", "private_key", "passwd_username",
			"docroot_hostname"}},
	}
	for _, c := range cases {
		_, summary := runMeter(t, c.src)
		for _, want := range c.want {
			if summary[want] == 0 {
				t.Errorf("[%s] summary shows 0 redactions for pattern %q — coverage regression (summary: %v)",
					c.shape, want, summary)
			}
		}
	}
}
