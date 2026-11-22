package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// DefaultPatterns returns the built-in redaction patterns enabled by default.
// These cover the patterns described in rules/defaults.conf.
//
// Order matters: more specific patterns (API keys, private keys, JWTs) run
// before less specific ones (phone, credit card) to prevent greedy matches
// from consuming substrings of longer token formats. Within the IP family,
// ipv4_private runs before ipv4 so the private-range toggle is meaningful —
// when both are enabled, RFC1918 addresses are attributed to ipv4_private
// and public ones to ipv4 (disabling ipv4_private alone never stops private
// addresses from being redacted while ipv4 is on; fail-safe direction).
func DefaultPatterns() []*Pattern {
	return []*Pattern{
		// Private keys (PEM blocks) — most specific, must run before credit card etc.
		{
			Name:     "private_key",
			Regex:    regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
			Category: "KEY",
			Enabled:  true,
		},

		// JWT tokens — specific structure, run before generic patterns
		{
			Name:     "jwt",
			Regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
			Category: "JWT",
			Enabled:  true,
		},

		// API keys — specific prefixes, run before phone/credit card
		{
			Name: "api_key_github",
			// Classic PATs (ghp_…) and fine-grained PATs (github_pat_…).
			// Fine-grained: github_pat_ + 22+ base62/underscore chars; classic:
			// ghp_/gho_/ghs_/ghu_/ghr_ + 36+ base62 chars. {22,} not {22} so
			// longer bodies still match; underscores allowed in fine-grained
			// bodies per GitHub's generator.
			Regex:    regexp.MustCompile(`\b(?:(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_openai",
			Regex:    regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_anthropic",
			Regex:    regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_aws",
			Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_aws_secret",
			Regex:    regexp.MustCompile(`\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_google",
			Regex:    regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_stripe",
			Regex:    regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_slack",
			Regex:    regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "api_key_gitlab",
			Regex:    regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},
		{
			Name:     "bearer_token",
			Regex:    regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}\b`),
			Category: "TOKEN",
			Enabled:  true,
		},

		// Database connection strings — MUST run before email: a DSN's
		// password@host part is email-shaped, and with email first the
		// email pattern consumed the userinfo while the DSN's scheme,
		// username and port survived mis-attributed (privacy meter,
		// 2026-11-21). More specific formats consume their span whole.
		{
			Name: "database_connection",
			// postgresql AND the driver-suffix forms (mongodb+srv is the
			// modern default; postgresql+psycopg2 / mysql+pymysql are the
			// SQLAlchemy spellings; mssql/amqp also carry credentials).
			// RE2 falls through a failed alternative to the next, so
			// branch ORDER does not matter (probed, Krabs round 1) — the
			// pre-v0.8.0 bug was the MISSING postgresql alternative
			// itself, which left the most common spelling unredacted
			// (privacy meter, 2026-11-21). Driver suffixes are enumerated,
			// not generalized — a `scheme+driver://` catch-all would eat
			// non-credential URLs like git+ssh://.
			Regex: regexp.MustCompile(`\b(?:postgresql\+psycopg2|postgresql|postgres\+psycopg2|postgres|mysql\+pymysql|mysql|mongodb\+srv|mongodb|mssql|amqp|rediss|redis)://[^\s]+`),
			// [^\s]+ swallows a trailing quote or comma into the span
			// (`export DSN="postgresql://…"` tokenizes including the
			// closing quote) — deliberate: greedy whole-token is the
			// fail-safe direction, and restore returns the exact span.
			// Cosmetic asymmetry documented (Krabs round 1, m5).
			Category: "DBURL",
			Enabled:  true,
		},

		// Email — specific structure with @
		{
			Name:     "email",
			Regex:    regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			Category: "EMAIL",
			Enabled:  true,
		},

		// Network — IPv4, IPv6, MAC
		{
			Name:     "ipv4",
			Regex:    regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`),
			Category: "IP",
			Enabled:  true,
		},
		// IPv6 — full 8-group form PLUS `::` compressed forms. The original
		// 8-group-only regex never matched compressed addresses — which is
		// most real-world IPv6 (`2001:db8::1` leaked whole; surfaced by a
		// clock-shaped canary, deepseek round 2 + privacy meter,
		// 2026-11-22). RE2 grammar notes: each `(?:h:){n}` group CONSUMES
		// its trailing colon, so a compressed form parses as
		// groups+bare-hex then `::` (a naive `{1,6}::` eats the first
		// colon of the pair and never matches); and `\b` never sits next
		// to a bare `:` (a boundary needs a word char on one side), which
		// is why `::`-LEADING forms need their own guarded pattern below.
		// Branches: (1) full form; (2) middle `::` (bare hex before it, so
		// `12:34:56::1` parses whole); (3) trailing `::` (config prefixes
		// like 2001:db8:1::). MACs (6 groups, no `::`) never match;
		// clocks have no `::`. Invalid 8-hex-digit tails
		// (12:34:56::deadbeef) tokenize only through the `::` — the
		// residue is inert hex.
		{
			Name:     "ipv6",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}::`),
			Category: "IP",
			Enabled:  true,
		},
		// ipv6_leading — `::`-prefixed forms (::1, ::ffff:1:2). Needs its
		// own pattern because `\b` cannot anchor before a bare `:`: the
		// guard `^|[^:\w\n\r]` consumes one preceding non-word char
		// (space, quote, start of line) and Group extracts ONLY the
		// address span, the same guard-consume/group-extract idiom the
		// syslog/accesslog hostname patterns use. The guard is what keeps
		// C++ off the menu: without it, `std::dec` / `my::cafe` would
		// tokenize (`::dec` is a leading-colon hex run). Bare `::` alone
		// (unspecified address) deliberately does not match — it is
		// punctuation-shaped and appears in code namespaces.
		{
			Name:     "ipv6_leading",
			Regex:    regexp.MustCompile(`(?m)(?:^|[^:\w\n\r])(::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})\b`),
			Category: "IP",
			Group:    1,
			Enabled:  true,
		},
		{
			Name:     "mac_address",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`),
			Category: "MAC",
			Enabled:  true,
		},

		// Credit card — 13-19 digits with optional separators, Luhn-checked.
		// Every real PAN carries a valid Luhn checksum; an order ID or
		// invoice number of the same length does not. The Validate hook
		// (v0.8.0) passes only Luhn-valid spans, so digit-shaped identifiers
		// pass through instead of becoming [TG:CC:N] noise. The window
		// widens to 19 digits (Krabs round 1, M1): real Maestro/UATP PANs
		// run that long, and with Luhn gating the wider window costs
		// nothing — a 19-digit order ID fails the checksum and passes
		// through. Known tradeoff, documented: a single-digit TYPO in a
		// real PAN fails its own checksum and passes through unredacted —
		// check-digit gating inherits this from the format itself; only
		// digit-pair transpositions that keep Luhn valid (e.g. 09↔90)
		// still tokenize. Edge, documented (deepseek round 2, MINOR,
		// probe-confirmed): 20+ digit runs only stay unmatched when
		// UNSEPARATED (\b cannot sit mid-run); a SEPARATED 20+ digit run
		// (`4111 1111 1111 1111 1234`) can match its 16-digit prefix plus
		// trailing separator, so a Luhn-valid prefix tokenizes and the
		// 4-digit residue stays visible. PANs never run 20+ digits, so the
		// residue is inert — no pattern consumes it and nothing sensitive
		// is 4 visible digits of a non-PAN. Accepted.
		{
			Name:     "credit_card",
			Regex:    regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`),
			Category: "CC",
			Enabled:  true,
			Validate: luhnValid,
		},

		// US Social Security Numbers
		{
			Name:     "ssn_us",
			Regex:    regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Category: "SSN",
			Enabled:  true,
		},

		// Phone — international form (+ prefix) and NANP form (3-3-4 with
		// optional separators). Bare 10-digit strings are deliberately
		// covered: for a redaction tool a missed number is worse than a
		// flagged order-ID. Structure-anchored (Group 1 = the number, the
		// leading context char survives): the match must start at a line
		// start or after a char that is NOT word/./:/- , so digit runs
		// glued to decimal points or time separators can never match —
		// the 2026-10-01 report had Apache timestamps
		// `15:07:51.712345 2026` eaten as a NANP number (712-345-2026).
		{
			Name:     "phone",
			Regex:    regexp.MustCompile(`(?m)(?:^|[^\w.:\-])(\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,5}[\s.\-]?\d{3,5}|\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})\b`),
			Category: "PHONE",
			Group:    1,
			Enabled:  true,
		},
	}
}

// ExtendedPatterns returns additional patterns used by server and paranoid presets.
// These are more aggressive patterns that may have higher false-positive rates.
func ExtendedPatterns() []*Pattern {
	extra := []*Pattern{
		// Private IPv4 ranges
		{
			Name:     "ipv4_private",
			Regex:    regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
			Category: "IP",
			Enabled:  false,
		},
		// Internal hostnames
		{
			Name:     "hostname_internal",
			Regex:    regexp.MustCompile(`\b[a-z0-9][a-z0-9\-]*\.(?:local|internal|lan)\b`),
			Category: "HOST",
			Enabled:  false,
		},
		// IBAN
		{
			Name:     "iban",
			Regex:    regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b`),
			Category: "IBAN",
			Enabled:  false,
		},
		// Passport numbers (simplified)
		{
			Name:     "passport",
			Regex:    regexp.MustCompile(`\b[A-Z]\d{8}\b`),
			Category: "PASSPORT",
			Enabled:  false,
		},
		// Generic high-entropy secrets (36+ char alphanumeric, likely a token)
		{
			Name:     "high_entropy_secret",
			Regex:    regexp.MustCompile(`\b[A-Za-z0-9_\-]{36,}\b`),
			Category: "SECRET",
			Enabled:  false,
		},

		// Syslog hostname — structure-anchored (Group 1 = hostname). A bare
		// hostname regex would false-positive on ordinary words; anchoring on
		// the line-start timestamp plus the `process[pid]:` tag shape keeps
		// precision — every real syslog line carries a process word before
		// the message colon. Dated prose ("Jan 15 09:30:00 all hands on
		// deck") lacks that tag and stays untouched. Timestamps, process and
		// pid all stay readable; only the hostname is tokenized.
		{
			Name: "syslog_hostname",
			// The timestamp alternatives cover the SHIELDED form too: the
			// content shield replaces timestamps with \x7f-padded sentinels
			// BEFORE patterns run, so without the sentinel alternative this
			// pattern went dead in the gateway pipeline entirely (v0.7.0
			// regression, found by the privacy meter 2026-11-21). The
			// unshielded alternatives stay for direct Redactor.Redact paths
			// (tests, tidegate text without shape detection).
			Regex:    regexp.MustCompile(`(?m)^(?:[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}|\x7f[A-Z]+\x7f)\s([a-zA-Z0-9][a-zA-Z0-9._-]*)\s+[a-zA-Z0-9._-]+(?:\[\d+\])?\s*:`),
			Category: "HOST",
			Group:    1,
			Enabled:  false,
		},

		// passwd username — structure-anchored (Group 1 = username). Anchored
		// on the rigid passwd/shadow line shape: name at line start, a
		// passwd-field value that only real account files use (x, !/!!, *,
		// a $…-hash, or empty for passwordless accounts), two numeric fields
		// (uid/gid or lastchg/min), and a trailing colon opening the next
		// field. Prose like "video:1920:1080:60" or "settings:default:100:200"
		// has a numeric or wordy second field and no trailing colon, so it
		// cannot match. The GECOS comment field and home path survive; only
		// the account name is tokenized.
		{
			Name:     "passwd_username",
			Regex:    regexp.MustCompile(`(?m)^([a-z_][a-z0-9_-]{0,31})[:!](?:x|!+|\*+|\$[^:]*)?(?::\d{1,10}){2}:`),
			Category: "USER",
			Group:    1,
			Enabled:  false,
			// Not in default set: only redact when the file itself looks like
			// passwd; otherwise every "user:pass" colon pair in prose matches.
		},

		// Access-log vhost — structure-anchored (Group 1 = vhost). Apache /
		// nginx combined-format logs with a leading virtual host have the
		// rigid shape `vhost[:port] client - - [dd/Mon/yyyy:HH:MM:SS +zzzz]`.
		// A bare hostname regex would false-positive on ordinary words and
		// public-looking domains in prose; the client field, the two dash
		// placeholders and the bracketed timestamp together are a shape prose
		// never produces, so only the vhost span is tokenized. Timestamp,
		// client (often an earlier [TG:IP:N] token — hence \S+) and the rest
		// of the line survive untouched. Runs LAST in patternNames so the IP
		// family and hostname_internal claim vhost values first: an IP-literal
		// vhost is then attributed to ipv4/ipv4_private, and an
		// already-tokenized vhost simply makes this pattern skip the line.
		// IPv6 bracket vhosts (`[2001:db8::1]:443 …`) are out of scope.
		{
			Name: "accesslog_hostname",
			// The bracket alternative accepts the SHIELDED timestamp form:
			// the content shield replaces the Apache/ISO stamp inside the
			// brackets with a \x7f sentinel before patterns run, which —
			// without the sentinel alternative — killed this pattern in the
			// gateway pipeline and silently undid the v0.6.2 vhost fix
			// (found by the privacy meter 2026-11-21).
			// The userid field accepts any token: real logs have logged-in
			// users (`… - alice [stamp]`), not only `- -` — the original
			// pattern demanded two dashes and silently skipped any line
			// with a real userid, leaking that vhost (privacy meter,
			// 2026-11-21). Identd stays literal `-` (universally dead
			// protocol) as the structural anchor.
			Regex: regexp.MustCompile(`(?m)^([a-zA-Z][a-zA-Z0-9._-]*` +
				`|\d[A-Za-z0-9]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*` +
				`|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?` +
				`[ 	]+\S+[ 	]+-[ 	]+\S+[ 	]+` +
				`\[(?:\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}[ 	]?[+-]\d{4}` +
				`|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?` +
				`|\x7f[A-Z]+\x7f)\]`),
			Category: "HOST",
			Group:    1,
			Enabled:  false,
		},

		// docroot hostname — structure-anchored (Group 1 = hostname
		// segment). Apache/Plesk DocumentRoot paths use the vhost's
		// hostname as a path segment: /var/www/<host>/htdocs,
		// /var/www/vhosts/<host>/, /srv/www/<host>/. Requiring the
		// trailing slash keeps plain files (…/index.html) from matching.
		// Found live by Earl 2026-10-01: `client denied by server
		// configuration: /var/www/myhost.com/htdocs/x.php` leaked the
		// vhost in path position (2026-10-01).
		{
			Name:     "docroot_hostname",
			Regex:    regexp.MustCompile(`(?m)(?i:\bvar/www(?:/vhosts)?/|\bsrv/www/)([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})/`),
			Category: "HOST",
			Group:    1,
			Enabled:  false,
		},

		// url_hostname — structure-anchored (Group 1 = host part). Any
		// scheme:// URL: referer fields in access logs, curl commands in
		// error logs, api endpoints in config dumps. Scheme, port and path
		// survive; only the host is tokenized. userinfo (user:pass@) stays
		// out of the group (it is its own credential pattern's business).
		{
			Name:     "url_hostname",
			Regex:    regexp.MustCompile(`(?m)(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)(?:[^\s/@]*@)?([a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})(?::\d{1,5})?(?:[/?#:]|\s)`),
			Category: "HOST",
			Group:    1,
			Enabled:  false,
		},
	}
	return append(DefaultPatterns(), extra...)
}

// patternNames is the registry of every known pattern, in evaluation order.
// AllPatterns and PatternNames are the single source of truth for what a
// [redaction.patterns] toggle can reference.
// Order matters: more specific patterns (API keys, private keys, JWTs,
// DSNs) run before less specific ones (email, phone, credit card) to
// prevent greedy matches from consuming substrings of longer formats.
// database_connection precedes email because a DSN's password@host part
// is email-shaped (`postgres://user:hunter2@db.internal:5432/prod`) —
// with email first, the email pattern consumed the userinfo and the
// DSN's scheme/username/port survived mis-attributed (privacy meter,
// 2026-11-21). Within the IP family, ipv4_private runs before ipv4 so
// the private-range toggle is meaningful — when both are enabled,
// RFC1918 addresses are attributed to ipv4_private and public ones to
// ipv4 (disabling ipv4_private alone never stops private addresses from
// being redacted while ipv4 is on; fail-safe direction).
var patternNames = []string{
	"private_key", "jwt", "database_connection",
	"api_key_github", "api_key_openai", "api_key_anthropic",
	"api_key_aws", "api_key_aws_secret", "api_key_google", "api_key_stripe",
	"api_key_slack", "api_key_gitlab", "bearer_token", "email", "ipv4_private",
	"ipv4", "ipv6", "ipv6_leading", "mac_address", "credit_card", "ssn_us",
	"phone", "hostname_internal", "iban", "passport", "high_entropy_secret",
	"syslog_hostname", "passwd_username", "accesslog_hostname",
	"docroot_hostname", "url_hostname",
}

// AllPatterns returns every known pattern (defaults plus extended). Extended
// patterns are disabled by default; enable them via [redaction.patterns].
func AllPatterns() []*Pattern {
	byName := make(map[string]*Pattern)
	for _, p := range ExtendedPatterns() {
		byName[p.Name] = p
	}
	ordered := make([]*Pattern, 0, len(patternNames))
	for _, name := range patternNames {
		if p, ok := byName[name]; ok {
			ordered = append(ordered, p)
		}
	}
	return ordered
}

// PatternNames returns the names of every known pattern, in evaluation order.
func PatternNames() []string {
	out := make([]string, len(patternNames))
	copy(out, patternNames)
	return out
}

// defaultPatternSet is the set of patterns enabled out of the box. Extended
// patterns (private IPs, internal hostnames, IBAN, passports, high-entropy
// secrets) are opt-in only — they must be explicitly enabled via
// [redaction.patterns] before they redact anything.
var defaultPatternSet = func() map[string]bool {
	m := make(map[string]bool)
	for _, p := range DefaultPatterns() {
		m[p.Name] = true
	}
	return m
}()

// IsDefaultPattern reports whether a pattern is part of the default set
// (enabled out of the box).
func IsDefaultPattern(name string) bool {
	return defaultPatternSet[name]
}

// Fingerprint hashes the active pattern set — names AND regex bodies — so a
// regex fix invalidates cached redaction output instead of serving stale
// results for the cache TTL. nil/empty names means "all patterns".
func Fingerprint(names []string) string {
	enabled := make(map[string]bool, len(names))
	for _, n := range names {
		enabled[n] = true
	}
	// AllPatterns is deterministic (declaration order).
	h := sha256.New()
	for _, p := range AllPatterns() {
		if len(names) > 0 && !enabled[p.Name] {
			continue
		}
		fmt.Fprintf(h, "%s|%s|%s|%d|%v\n", p.Name, p.Regex.String(), p.Category, p.Group, p.Validate != nil)
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// NewWithNames creates a Redactor with the named patterns enabled (plus the
// defaults for any name not recognized). Unknown names are ignored so that
// configs referencing future/renamed patterns don't crash the gateway.
func NewWithNames(enabled []string) *Redactor {
	enabledSet := make(map[string]bool, len(enabled))
	for _, n := range enabled {
		enabledSet[n] = true
	}
	patterns := make([]*Pattern, 0)
	for _, p := range AllPatterns() {
		p2 := *p
		p2.Enabled = enabledSet[p.Name] // absent name → disabled
		patterns = append(patterns, &p2)
	}
	return &Redactor{
		mapping:  make(map[string]string),
		reverse:  make(map[string]string),
		counters: make(map[string]int64),
		seen:     make(map[string]bool),
		patterns: patterns,
	}
}
