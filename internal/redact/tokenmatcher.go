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
	mappings map[string]string // exact: "[TG:IP:1]" → "203.0.113.42"
	fuzzy    []fuzzyPattern
}

type fuzzyPattern struct {
	regex        *regexp.Regexp
	category     string
	captureGroup int
}

// tokenRegex matches the canonical [TG:CATEGORY:N] format. Categories may
// contain digits and underscores (e.g. JSON_SECRET).
var tokenRegex = regexp.MustCompile(`\[TG:([A-Z0-9_]+):(\d+)\]`)

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
	for cat := range categories {
		pattern := `["'\x60]?TG[:_]` + regexp.QuoteMeta(cat) + `[:_](\d+)["'\x60]?`
		tm.fuzzy = append(tm.fuzzy, fuzzyPattern{
			regex:        regexp.MustCompile(pattern),
			category:     cat,
			captureGroup: 1,
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

	// Phase 1: exact matches [TG:CATEGORY:N]
	result := tokenRegex.ReplaceAllStringFunc(content, func(match string) string {
		if original, ok := tm.mappings[match]; ok {
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
			// Build the canonical token and look it up
			canonical := "[TG:" + fp.category + ":" + num + "]"
			if original, ok := tm.mappings[canonical]; ok {
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

// SanitizeForLog strips token values from a string for safe logging.
// Replaces [TG:CAT:N] with [TG:CAT:N] (no original values exposed).
func SanitizeForLog(s string) string {
	return tokenRegex.ReplaceAllStringFunc(s, func(match string) string {
		subs := tokenRegex.FindStringSubmatch(match)
		if len(subs) >= 3 {
			return "[TG:" + subs[1] + ":" + subs[2] + "]"
		}
		return match
	})
}

// TokenPrefix returns the common prefix for all redaction tokens.
const TokenPrefix = "[TG:"

// IsTokenContent checks if content contains any redaction tokens.
func IsTokenContent(s string) bool {
	return strings.Contains(s, TokenPrefix)
}
