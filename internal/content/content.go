// Package content implements content-shape detection and structure-aware
// redaction for Tidegate.
//
// Regex redaction alone cannot tell a secret from structure: the v0.6.2/0.6.3
// false positives (a phone pattern eating an Apache timestamp, a hostname
// hiding in a DocumentRoot path) were both shape problems. This package
// detects the shape of a block first and applies the right transform:
//
//   - JSON: values under sensitive keys are redacted wholesale, catching
//     secrets that no regex recognises (base64 blobs, names, DSNs).
//   - Logs and prose: timestamps are shielded before pattern redaction and
//     restored afterwards, so patterns never fire inside a timestamp.
//
// Everything here preserves byte layout: no re-encoding, no re-ordering, so
// provider prompt caches stay warm.
package content

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Kind is a detected content shape.
type Kind string

const (
	KindText Kind = "text"
	KindJSON Kind = "json"
	KindLog  Kind = "log"
	KindCode Kind = "code"
	KindDiff Kind = "diff"
)

var (
	isoTimestamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	apacheStamp  = regexp.MustCompile(`\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?\b`)
	syslogStamp  = regexp.MustCompile(`\b[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}\b`)
	// clockStamp guards against digit-pair runs longer than a clock: a MAC
	// tail (`02:42:ac:11:00:03`) or a 2-digit-group IPv6 (`12:34:56:78:…`)
	// contains a `\d{2}:\d{2}:\d{2}` shape, and shielding it broke the
	// mac_address/ipv6 patterns mid-span (found by the privacy meter,
	// 2026-11-21). The leading guard (`^|[^:\w\n\r]`) rejects a match
	// preceded by `:`, a word char or a newline: mid-run (MAC) positions
	// never match, and a clock at line start is taken by the zero-width `^`
	// so the preceding newline survives the SHIELDED intermediate (a
	// swallowed newline would merge lines and break every (?m)^-anchored
	// pattern on the next line — Krabs review round 1, 2026-11-21). The
	// leading guard char (space, quote, bracket) is re-emitted by the
	// callback, never swallowed into the sentinel.
	//
	// The trailing consumption `(?::[0-9a-fA-F]{1,4}|::)*` eats any further
	// colon-joined hex groups (IPv6 groups run 1-4 digits, not just the 2
	// MACs use) AND the `::` compression separator. Without the `::`
	// alternative and the {1,4} width, a valid IPv6 whose first three
	// groups look like a clock (`12:34:56::1`,
	// `12:34:56:7:89:ab:cd:ef`) matched only the `12:34:56` prefix,
	// classified as a CLEAN clock, and got shielded — splitting the
	// address so ipv6 never fired and the tail groups leaked upstream
	// (deepseek-v4-pro review round 2, 2026-11-22, probe-confirmed). The
	// shield callback then decides: a match with more than two colons is
	// a longer colon-run (MAC/IPv6-style), returned UNCHANGED so
	// mac_address/ipv6 can fire on the full span; a clean three-pair
	// clock becomes a sentinel. Go RE2 has no lookahead, so the trailing
	// context must be consumed and classified rather than tested. A clock
	// glued to further hex pairs (`10:15:23:ab:cd:ef`) is classified as
	// a run and left in place — nothing in the pattern set can eat that
	// shape, so the clock riding along is harmless.
	// Known tradeoff: a real clock embedded in a longer colon-run is not
	// shielded (documented, accepted — shields exist to protect the clock
	// FROM patterns, and no pattern matches it inside a run).
	clockStamp    = regexp.MustCompile(`(?m)(?:^|[^:\w\n\r])\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?::[0-9a-fA-F]{1,4}|::)*`)
	dateOnlyStamp = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)

	logLine   = regexp.MustCompile(`(?m)^(?:[^\n]{0,140}(?:\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}|\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\b[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\b\d{2}:\d{2}:\d{2}[.,]\d+)|(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|NOTICE)\b)`)
	levelWord = regexp.MustCompile(`\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|NOTICE)\b`)
	diffHunk  = regexp.MustCompile(`(?m)^@@ .* @@`)
	diffFile  = regexp.MustCompile(`(?m)^(?:---|\+\+\+) `)
	codeHint  = regexp.MustCompile(`(?m)^\s*(?:package|import|func|type|class|def|#include|using namespace)\b|^\s*(?://|/\*|\*)\s|=>|\breturn\b`)
)

// Detect classifies content by shape. It is intentionally cheap and
// conservative: when no strong signal is present it returns KindText.
func Detect(s string) Kind {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return KindText
	}

	if (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed)) {
		return KindJSON
	}

	lines := strings.Split(trimmed, "\n")
	if diffHunk.MatchString(trimmed) && diffFile.MatchString(trimmed) {
		return KindDiff
	}

	logScore := 0
	for _, line := range lines {
		if logLine.MatchString(line) {
			logScore++
		}
	}
	if logScore >= 2 || (logScore == 1 && levelWord.MatchString(trimmed) && len(lines) == 1) {
		return KindLog
	}

	codeScore := 0
	for _, line := range lines {
		if codeHint.MatchString(line) {
			codeScore++
		}
		if codeScore >= 2 {
			return KindCode
		}
	}

	return KindText
}

// sensitiveKeys are compared after lowercasing and removing "_", "-" and ".".
//
// Selection rule (v0.8.0): a key belongs here only when its value is
// sensitive BY CONVENTION in every realistic use — a field named cvv is a
// card verification code, a field named password is a password, whatever the
// bytes inside look like. Keys whose value is routinely NOT sensitive (name,
// phone, email, pin — GPIO pin numbers, person names in schema discussions)
// stay OUT: the shape patterns own those, and wholesale replacement would
// destroy data the agent legitimately works with. This mirrors Penteos's
// field-name masking layer (penteos.com, AGPL-3.0) — the idea, not the code.
var sensitiveKeys = map[string]bool{
	"password":           true,
	"passwd":             true,
	"pwd":                true,
	"passphrase":         true,
	"secret":             true,
	"clientsecret":       true,
	"secretkey":          true,
	"apisecret":          true,
	"apikey":             true,
	"accesstoken":        true,
	"refreshtoken":       true,
	"idtoken":            true,
	"token":              true,
	"authtoken":          true,
	"authorization":      true,
	"bearer":             true,
	"cookie":             true,
	"setcookie":          true,
	"sessionid":          true,
	"sessiontoken":       true,
	"privatekey":         true,
	"accesskey":          true,
	"awssecretaccesskey": true,
	"credentials":        true,
	"connectionstring":   true,
	"databaseurl":        true,
	"dburl":              true,
	"dsn":                true,
	"dsnstring":          true,
	"jwt":                true,
	// v0.8.0 — financial: a PAN, CVV or bank account number under its
	// conventional key is sensitive regardless of the bytes it holds.
	// "pan" itself stays OUT (Krabs round 1, m2): it fails the selection
	// rule — recipe JSONs (pan = bread in Spanish), network payloads and
	// device namespaces all use it non-sensitively. "pannumber" (the
	// Indian tax ID key) passes the rule and is in.
	"cvv":                  true,
	"cvv2":                 true,
	"cvc":                  true,
	"cvc2":                 true,
	"cardverificationcode": true,
	"cardnumber":           true,
	"creditcard":           true,
	"creditcardnumber":     true,
	"cardno":               true,
	"pannumber":            true,
	"iban":                 true,
	"accountnumber":        true,
	"bankaccount":          true,
	"routingnumber":        true,
	// v0.8.0 — government identifiers under their conventional keys.
	"ssn":                  true,
	"socialsecuritynumber": true,
	"passportnumber":       true,
	"passportno":           true,
	// v0.8.0 — header-style keys that appear inside JSON bodies.
	"xapikey":      true,
	"xauthtoken":   true,
	"xaccesstoken": true,
}

// IsSensitiveKey reports whether a JSON key conventionally holds a secret.
func IsSensitiveKey(key string) bool {
	norm := strings.ToLower(strings.TrimSpace(key))
	norm = strings.NewReplacer("_", "", "-", "", ".", "").Replace(norm)
	return sensitiveKeys[norm]
}

// jsonKey matches a JSON object key and its colon. Values are located with a
// small scanner so strings, numbers, booleans, nulls, objects and arrays all
// come under a sensitive key — not just string values.
var jsonKey = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:`)

// RedactJSONKeys replaces the value of every sensitive JSON key using fn.
// It returns the rewritten document and the number of values replaced.
//
// fn receives the decoded key and the value as text (JSON is decoded for
// strings; numbers/booleans/null keep their literal form; objects and arrays
// keep their raw JSON). Tokens replace string values in place and are quoted
// for every other type, so the document stays valid.
func RedactJSONKeys(src string, fn func(key, value string) string) (string, int) {
	matches := jsonKey.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return src, 0
	}
	var b strings.Builder
	b.Grow(len(src))
	last := 0
	count := 0
	for _, m := range matches {
		keyStart, keyEnd := m[2], m[3]
		if keyStart < 0 || keyEnd < 0 {
			continue
		}
		key, err := unquoteJSON(src[keyStart:keyEnd])
		if err != nil || !IsSensitiveKey(key) {
			continue
		}

		valueStart := skipJSONSpace(src, m[1])
		if valueStart >= len(src) {
			continue
		}
		valueEnd, isString := scanJSONValue(src, valueStart)
		if valueEnd <= valueStart {
			continue
		}

		var value string
		if isString {
			if valueEnd-valueStart < 2 {
				continue
			}
			value, err = unquoteJSON(src[valueStart+1 : valueEnd-1])
			if err != nil {
				continue
			}
		} else {
			value = strings.TrimSpace(src[valueStart:valueEnd])
		}
		if value == "" || value == "null" || strings.HasPrefix(value, "[TG:") {
			continue
		}

		token := fn(key, value)
		if isString {
			b.WriteString(src[last : valueStart+1])
			b.WriteString(token)
			last = valueEnd - 1
		} else {
			b.WriteString(src[last:valueStart])
			b.WriteString(`"` + token + `"`)
			last = valueEnd
		}
		count++
	}
	if count == 0 {
		return src, 0
	}
	b.WriteString(src[last:])
	out := b.String()
	// Never hand back malformed JSON: if the rewrite broke the document,
	// keep the original and let pattern redaction handle it.
	if json.Valid([]byte(strings.TrimSpace(out))) {
		return out, count
	}
	return src, 0
}

func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// scanJSONValue returns the exclusive end of the JSON value starting at i and
// whether that value is a string.
func scanJSONValue(s string, i int) (int, bool) {
	if i >= len(s) {
		return i, false
	}
	if s[i] == '"' {
		j := i + 1
		for j < len(s) {
			if s[j] == '\\' {
				j += 2
				continue
			}
			if s[j] == '"' {
				return j + 1, true
			}
			j++
		}
		return i, false
	}
	if s[i] == '{' || s[i] == '[' {
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '"':
				j++
				for j < len(s) {
					if s[j] == '\\' {
						j++
					} else if s[j] == '"' {
						break
					}
					j++
				}
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, false
				}
			}
		}
		return i, false
	}
	j := i
	for j < len(s) && !strings.ContainsRune(",}] \t\n\r", rune(s[j])) {
		j++
	}
	return j, false
}

// unquoteJSON decodes a JSON string body (without the surrounding quotes).
// encoding/json handles \uXXXX escapes and surrogate pairs, which
// strconv.Unquote rejects — a password value containing an escaped emoji must
// still be redacted.
func unquoteJSON(raw string) (string, error) {
	var out string
	if err := json.Unmarshal([]byte(`"`+raw+`"`), &out); err != nil {
		return "", err
	}
	return out, nil
}

// ShieldTimestamps temporarily replaces timestamp spans with inert sentinels
// so pattern redaction cannot fire inside them. The returned restore function
// puts the original spans back.
//
// This is the structural counterpart to the v0.6.3 phone false positive: the
// pattern was correct for phone numbers but blind to the shape of a log line.
func ShieldTimestamps(src string) (string, func(string) string) {
	if src == "" {
		return src, func(s string) string { return s }
	}
	restore := map[string]string{}
	out := src
	next := 0

	shield := func(re *regexp.Regexp) {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			key := sentinel(next)
			next++
			restore[key] = match
			return key
		})
	}
	shield(isoTimestamp)
	shield(apacheStamp)
	shield(syslogStamp)
	// clockStamp matches clean three-pair clocks AND longer hex-pair runs
	// (MAC/IPv6 fragments — RE2 has no lookahead, so the trailing pairs
	// are consumed and classified here). Only the clean clock is shielded;
	// a longer colon-run must survive so mac_address/ipv6 can fire on the
	// full span (privacy meter regression, 2026-11-21).
	//
	// The leading guard char (space, quote, bracket) is RE-EMITTED in
	// place, not swallowed into the sentinel: patterns evaluate the
	// shielded intermediate, and a consumed quote or bracket would mangle
	// JSON-shaped spans there, while a consumed newline would merge lines
	// and break (?m)^-anchored patterns on the next line (Krabs review
	// round 1, 2026-11-21). Only the clock itself is stored for restore;
	// at a line-start match (^ is zero-width) the match begins with a
	// digit and the prefix is empty.
	out = clockStamp.ReplaceAllStringFunc(out, func(match string) string {
		if strings.Count(match, ":") > 2 {
			return match // MAC/IPv6 fragment, not a clock — leave in place
		}
		prefix := ""
		if match[0] < '0' || match[0] > '9' {
			_, size := utf8.DecodeRuneInString(match)
			prefix = match[:size]
		}
		key := sentinel(next)
		next++
		restore[key] = match[len(prefix):]
		return prefix + key
	})
	shield(dateOnlyStamp)

	if len(restore) == 0 {
		return out, func(s string) string { return s }
	}
	return out, func(s string) string {
		for k, v := range restore {
			s = strings.ReplaceAll(s, k, v)
		}
		return s
	}
}

// sentinel builds DEL-delimited markers (0x7f is legal unescaped in JSON and
// matches no Tidegate pattern).
func sentinel(n int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var b []byte
	b = append(b, 0x7f)
	for n >= 0 {
		b = append(b, letters[n%26])
		n = n/26 - 1
		if n < 0 {
			break
		}
	}
	b = append(b, 0x7f)
	return string(b)
}
