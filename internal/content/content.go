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
	"strconv"
	"strings"
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
	isoTimestamp  = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	apacheStamp   = regexp.MustCompile(`\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?\b`)
	syslogStamp   = regexp.MustCompile(`\b[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}\b`)
	clockStamp    = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?\b`)
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

// sensitiveKeys are compared after lowercasing and removing "_" and "-".
var sensitiveKeys = map[string]bool{
	"password":           true,
	"passwd":             true,
	"passphrase":         true,
	"secret":             true,
	"clientsecret":       true,
	"secretkey":          true,
	"apikey":             true,
	"accesstoken":        true,
	"refreshtoken":       true,
	"idtoken":            true,
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
}

// IsSensitiveKey reports whether a JSON key conventionally holds a secret.
func IsSensitiveKey(key string) bool {
	norm := strings.ToLower(strings.TrimSpace(key))
	norm = strings.NewReplacer("_", "", "-", "", ".", "").Replace(norm)
	return sensitiveKeys[norm]
}

// jsonStringKV matches "key": "value" pairs in raw JSON without re-encoding
// the document. Group 1 is the key, group 2 the value; either may contain
// escapes.
var jsonStringKV = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// RedactJSONKeys replaces the value of every sensitive JSON key using fn.
// It returns the rewritten document and the number of values replaced.
//
// fn receives the decoded key and the decoded value. The returned string is
// inserted verbatim, so it must be JSON-string-safe (Tidegate tokens are).
func RedactJSONKeys(src string, fn func(key, value string) string) (string, int) {
	matches := jsonStringKV.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return src, 0
	}
	var b strings.Builder
	b.Grow(len(src))
	last := 0
	count := 0
	for _, m := range matches {
		keyStart, keyEnd := m[2], m[3]
		valueStart, valueEnd := m[4], m[5]
		if keyStart < 0 || keyEnd < 0 || valueStart < 0 || valueEnd < 0 {
			continue
		}
		key, err := strconv.Unquote(`"` + src[keyStart:keyEnd] + `"`)
		if err != nil {
			continue
		}
		if !IsSensitiveKey(key) {
			continue
		}
		rawValue := src[valueStart:valueEnd]
		value, err := strconv.Unquote(`"` + rawValue + `"`)
		if err != nil {
			continue
		}
		if value == "" || strings.HasPrefix(value, "[TG:") {
			continue
		}
		b.WriteString(src[last:valueStart])
		b.WriteString(fn(key, value))
		last = valueEnd
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
	shield(clockStamp)
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
