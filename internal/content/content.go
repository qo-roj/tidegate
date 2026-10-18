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
