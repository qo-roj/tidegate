package redact

import "regexp"

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
		{
			Name:     "ipv6",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			Category: "IP",
			Enabled:  true,
		},
		{
			Name:     "mac_address",
			Regex:    regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`),
			Category: "MAC",
			Enabled:  true,
		},

		// Database connection strings
		{
			Name:     "database_connection",
			Regex:    regexp.MustCompile(`\b(?:postgres|mysql|mongodb|redis)://[^\s]+`),
			Category: "DBURL",
			Enabled:  true,
		},

		// Credit card — 13-16 digits with optional separators
		{
			Name:     "credit_card",
			Regex:    regexp.MustCompile(`\b(?:\d[ \-]?){13,16}\b`),
			Category: "CC",
			Enabled:  true,
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
		// flagged order-ID. Word boundaries keep it from matching inside
		// longer digit runs; IPs/dates/SSNs don't fit the 3-3-4 shape.
		{
			Name:     "phone",
			Regex:    regexp.MustCompile(`(?:\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,5}[\s.\-]?\d{3,5}|\(?\b\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b)`),
			Category: "PHONE",
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
			Name:     "syslog_hostname",
			Regex:    regexp.MustCompile(`(?m)^(?:[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s([a-zA-Z0-9][a-zA-Z0-9._-]*)\s+[a-zA-Z0-9._-]+(?:\[\d+\])?\s*:`),
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
			Regex: regexp.MustCompile(`(?m)^([a-zA-Z][a-zA-Z0-9._-]*` +
				`|\d[A-Za-z0-9]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*` +
				`|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?` +
				`[ 	]+\S+[ 	]+-[ 	]+-[ 	]+` +
				`\[(?:\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}[ 	]?[+-]\d{4}` +
				`|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\]`),
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
var patternNames = []string{
	"private_key", "jwt", "api_key_github", "api_key_openai", "api_key_anthropic",
	"api_key_aws", "api_key_aws_secret", "api_key_google", "api_key_stripe",
	"api_key_slack", "api_key_gitlab", "bearer_token", "email", "ipv4_private",
	"ipv4", "ipv6", "mac_address", "database_connection", "credit_card", "ssn_us",
	"phone", "hostname_internal", "iban", "passport", "high_entropy_secret",
	"syslog_hostname", "passwd_username", "accesslog_hostname",
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
		patterns: patterns,
	}
}
