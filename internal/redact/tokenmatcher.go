package redact

import (
	"regexp"
	"strings"
)

// TokenMatcher provides exact and fuzzy reverse-mapping of redaction tokens.
// It handles cases where the cloud model reformats tokens (quotes, backticks,
// stripped brackets, underscore substitution).
//
// Token format: [TG:CATEGORY:N] (e.g. [TG:IP:1])
//
// Fuzzy matches catch:
//   - "TG:IP:1"      (quotes stripped)
//   - `TG:IP:1`      (backticks stripped)
//   - TG:IP:1        (brackets stripped)
//   - TG_IP_1        (underscores substituted)
type TokenMatcher struct {
	mappings map[string]string // exact: "[TG:IP:1:9f3c1a2b]" → "203.0.113.42"
	fuzzy    []fuzzyPattern
}

// expandNested resolves tokens embedded in another token's original value.
func expandNested(value string, mappings map[string]string, depth int) string {
	if depth > 10 {
		return value
	}
	for token, original := range mappings {
		if strings.Contains(value, token) {
			value = strings.ReplaceAll(value, token, expandNested(original, mappings, depth+1))
		}
	}
	return value
}

type fuzzyPattern struct {
	regex        *regexp.Regexp
	category     string
	captureGroup int
	macGroup     int
}

// tokenRegex matches the canonical [TG:CATEGORY:N] format. Categories may
// contain digits and underscores (e.g. JSON_SECRET).
var tokenRegex = regexp.MustCompile(`\[TG:([A-Z0-9_]+):(\d+):([0-9a-f]{8})\]`)

// NewTokenMatcher creates a TokenMatcher from a redactor's current mapping.
// Only tokens this request is allowed to resolve are included (see
// Redactor.Snapshot).
func NewTokenMatcher(r *Redactor) *TokenMatcher {
	return NewTokenMatcherFromMap(r.Snapshot())
}

// NewTokenMatcherFromMap builds a matcher from an explicit token→original map.
func NewTokenMatcherFromMap(mappings map[string]string) *TokenMatcher {
	tm := &TokenMatcher{
		mappings: make(map[string]string, len(mappings)),
	}

	// Copy mappings and build fuzzy patterns for each category
	categories := make(map[string]bool)
	for token, original := range mappings {
		tm.mappings[token] = original

		// Extract category from token
		matches := tokenRegex.FindStringSubmatch(token)
		if len(matches) >= 2 {
			categories[matches[1]] = true
		}
	}

	// Build fuzzy patterns for each category present in the mapping.
	// Quote/backtick wrappers are optional; underscores may replace colons.
	// The MAC suffix must match too — stripping it must not resolve.
	for cat := range categories {
		pattern := `["'\x60]?TG[:_]` + regexp.QuoteMeta(cat) + `[:_](\d+)[:_]([0-9a-f]{8})["'\x60]?`
		tm.fuzzy = append(tm.fuzzy, fuzzyPattern{
			regex:        regexp.MustCompile(pattern),
			category:     cat,
			captureGroup: 1,
			macGroup:     2,
		})
	}

	return tm
}

// Restore replaces all tokens (exact and fuzzy) in the given content with
// their original values. Returns the restored content.
func (tm *TokenMatcher) Restore(content string) string {
	if len(tm.mappings) == 0 {
		return content
	}

	// Expand nested tokens inside mapping values first: a redacted
	// connection string may embed another token, and restoring only the
	// outer value would strand the inner one.
	expanded := make(map[string]string, len(tm.mappings))
	for token, original := range tm.mappings {
		expanded[token] = expandNested(original, tm.mappings, 0)
	}

	// Phase 1: exact matches [TG:CATEGORY:N:MAC]
	result := tokenRegex.ReplaceAllStringFunc(content, func(match string) string {
		if original, ok := expanded[match]; ok {
			return original
		}
		return match // unresolved token — leave as-is
	})

	// Phase 2: fuzzy matches (quotes stripped, brackets stripped, underscores)
	for _, fp := range tm.fuzzy {
		result = fp.regex.ReplaceAllStringFunc(result, func(match string) string {
			// Extract the number from the fuzzy match
			subs := fp.regex.FindStringSubmatch(match)
			if len(subs) < 2 {
				return match
			}
			num := subs[fp.captureGroup]
			mac := subs[fp.macGroup]
			// Build the canonical token and look it up
			canonical := "[TG:" + fp.category + ":" + num + ":" + mac + "]"
			if original, ok := expanded[canonical]; ok {
				return original
			}
			return match // unresolved — leave as-is
		})
	}

	return result
}

// HasMappings returns true if there are any mappings to restore.
func (tm *TokenMatcher) HasMappings() bool {
	return len(tm.mappings) > 0
}

// UnresolvedTokens scans content for any remaining [TG:*:*] tokens that
// couldn't be resolved. Returns the list of unresolved tokens found.
func (tm *TokenMatcher) UnresolvedTokens(content string) []string {
	var unresolved []string

	matches := tokenRegex.FindAllString(content, -1)
	for _, m := range matches {
		if _, ok := tm.mappings[m]; !ok {
			unresolved = append(unresolved, m)
		}
	}

	return unresolved
}

// SanitizeForLog returns content that is safe to log: tokens contain no
// original values, so canonical tokens pass through unchanged. Any token-like
// text that does not match the canonical shape is left as-is too.
func SanitizeForLog(s string) string {
	return s
}

// TokenPrefix returns the common prefix for all redaction tokens.
const TokenPrefix = "[TG:"

// IsTokenContent checks if content contains any redaction tokens.
func IsTokenContent(s string) bool {
	return strings.Contains(s, TokenPrefix)
}
