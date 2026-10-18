// Package redact provides pattern-based content redaction for the Tidegate
// gateway. It scans content for sensitive data (IPs, emails, API keys, etc.)
// and replaces matches with opaque tokens, maintaining an in-memory mapping
// for reverse restoration in responses.
//
// Token format: [TG:CATEGORY:N] (e.g. [TG:IP:1], [TG:EMAIL:3])
// The TG: prefix makes collisions with natural text extremely unlikely.
package redact

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// StatelessTokenSuffix marks tokens allocated without a session vault. It is
// deliberately constant: per-request mappings are never resolvable outside
// the request that created them.
const StatelessTokenSuffix = "00000000"

// randomHex returns n random hex characters.
func randomHex(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(buf)[:n]
}

// randomToken builds a syntactically valid token that has no vault mapping,
// so it stays redacted but cannot be restored.
func randomToken(category string) string {
	return fmt.Sprintf("[TG:%s:0:%s]", category, randomHex(8))
}

// Pattern defines a single redaction pattern.
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Category string // token category, e.g. "IP", "EMAIL", "KEY"
	Enabled  bool
	// Group, when > 0, redacts only that capture group's span instead of the
	// whole match. Used for structure-anchored patterns where context must
	// survive: e.g. a syslog line's timestamp anchors the match but must stay
	// readable, while the hostname (group 1) is redacted. Go's RE2 has no
	// lookbehind, so group-span replacement is the only way to express this.
	Group int
}

// TokenStore is the persistence backend for session-scoped token mappings.
// When configured, tokens survive across requests and are allocated
// deterministically per session, so a token echoed back in conversation
// history always resolves to the value it originally replaced.
type TokenStore interface {
	Token(session, category, original string) (string, error)
	Tokens(session string) (map[string]string, error)
}

// Redactor holds active patterns and the token mapping for the current
// request. With a TokenStore attached, mappings are session-scoped and
// persistent; without one it behaves as before (per-request, in-memory).
type Redactor struct {
	patterns []*Pattern
	mapping  map[string]string // token → original value
	reverse  map[string]string // original value → token (for O(1) dedup)
	mu       sync.Mutex
	counters map[string]int64 // per-category counter for unique tokens

	store   TokenStore
	session string
	// seen holds tokens observed in the incoming request (history) plus
	// tokens allocated for it. Only these may be restored in a response:
	// a model that invents or quotes an unrelated token cannot use the
	// gateway as an oracle for values from another conversation.
	seen map[string]bool
}

// New creates a Redactor with default patterns. Use WithPatterns to customize.
func New() *Redactor {
	return &Redactor{
		mapping:  make(map[string]string),
		reverse:  make(map[string]string),
		counters: make(map[string]int64),
		patterns: DefaultPatterns(),
		seen:     make(map[string]bool),
	}
}

// WithStore attaches a persistent store and session. Returns the redactor for
// chaining.
func (r *Redactor) WithStore(store TokenStore, session string) *Redactor {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
	r.session = session
	return r
}

// Session returns the session this redactor is scoped to.
func (r *Redactor) Session() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.session
}

// tokenRe matches the canonical Tidegate token shape, including the
// session-bound MAC suffix.
var tokenRe = regexp.MustCompile(`\[TG:[A-Z0-9_]+:[0-9]+:[0-9a-f]{8}\]`)

// NoteTokens records every Tidegate token present in content as "seen" for
// this request. Call it for incoming conversation history so historical
// tokens remain resolvable in the response, while unrelated tokens stay
// opaque.
func (r *Redactor) NoteTokens(content string) {
	matches := tokenRe.FindAllString(content, -1)
	if len(matches) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range matches {
		r.seen[m] = true
	}
}

// Allocate returns a token for an arbitrary category/value pair. Used by
// structure-aware redaction (e.g. sensitive JSON keys) which has no Pattern.
func (r *Redactor) Allocate(category, original string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allocateCategory(category, original)
}

// WithPatterns replaces the pattern set. Returns the redactor for chaining.
func (r *Redactor) WithPatterns(patterns []*Pattern) *Redactor {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.patterns = patterns
	return r
}

// EnablePattern enables a named pattern. Returns false if not found.
func (r *Redactor) EnablePattern(name string) bool {
	return r.setPatternEnabled(name, true)
}

// DisablePattern disables a named pattern. Returns false if not found.
func (r *Redactor) DisablePattern(name string) bool {
	return r.setPatternEnabled(name, false)
}

func (r *Redactor) setPatternEnabled(name string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.patterns {
		if p.Name == name {
			p.Enabled = enabled
			return true
		}
	}
	return false
}

// Redact scans content and replaces all sensitive matches with tokens.
// Returns the redacted content and a summary of what was redacted.
func (r *Redactor) Redact(content string) (string, Summary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := Summary{}
	result := content

	for _, p := range r.patterns {
		if !p.Enabled {
			continue
		}

		// Use ReplaceAllStringFunc so each distinct match value gets its own
		// token. ReplaceAllString would replace ALL matches with a single token,
		// collapsing distinct values (e.g. two different IPs → same token).
		matchCount := 0
		if p.Group > 0 {
			// Structure-anchored pattern: redact only the capture-group span,
			// keep the anchoring context (timestamp, field separators).
			result = p.Regex.ReplaceAllStringFunc(result, func(match string) string {
				loc := p.Regex.FindStringSubmatchIndex(match)
				if len(loc) < 2*p.Group+2 {
					return match // group missing in this match — leave untouched
				}
				start, end := loc[2*p.Group], loc[2*p.Group+1]
				if start < 0 || end < 0 || start >= end {
					return match // group didn't participate — leave untouched
				}
				value := match[start:end]
				token := r.allocateToken(p, value)
				matchCount++
				return match[:start] + token + match[end:]
			})
		} else {
			result = p.Regex.ReplaceAllStringFunc(result, func(match string) string {
				matchCount++
				return r.allocateToken(p, match)
			})
		}
		if matchCount > 0 {
			summary[p.Name] = matchCount
		}
	}

	return result, summary
}

// Restore reverse-maps tokens in a response back to their original values.
// This lets the agent work with real data in the cloud model's response.
//
// Only tokens seen in the request (or allocated for it) are restored. A model
// that hallucinates a token, or quotes one from a different conversation,
// cannot use the gateway to recover values it was never given.
//
// Mapping values may themselves contain tokens (e.g. a database_connection
// match whose original embeds an EMAIL token redacted by an earlier
// pattern). Values are expanded transitively before replacement so nested
// tokens never strand, and tokens are sorted longest-first with a
// deterministic alphabetical tiebreak.
func (r *Redactor) Restore(content string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	snapshot := r.snapshotLocked()
	if len(snapshot) == 0 {
		return content
	}

	expanded := make(map[string]string, len(snapshot))
	for token, original := range snapshot {
		expanded[token] = expandValue(original, snapshot, 0)
	}

	tokens := make([]string, 0, len(expanded))
	for token := range expanded {
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool {
		if len(tokens[i]) != len(tokens[j]) {
			return len(tokens[i]) > len(tokens[j])
		}
		return tokens[i] < tokens[j] // deterministic order for equal lengths
	})

	result := content
	for _, token := range tokens {
		result = strings.ReplaceAll(result, token, expanded[token])
	}
	return result
}

// Snapshot returns the token→original view this request is allowed to use:
// everything allocated for it plus historical tokens that appeared in the
// incoming request.
func (r *Redactor) Snapshot() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotLocked()
}

func (r *Redactor) snapshotLocked() map[string]string {
	out := make(map[string]string, len(r.mapping))
	for token, original := range r.mapping {
		out[token] = original
	}
	if r.store != nil && r.session != "" {
		if stored, err := r.store.Tokens(r.session); err == nil {
			for token, original := range stored {
				if !r.seen[token] {
					continue
				}
				if _, ok := out[token]; !ok {
					out[token] = original
				}
			}
		}
	}
	return out
}

// expandValue resolves redaction tokens embedded in a mapping value.
func expandValue(value string, snapshot map[string]string, depth int) string {
	if depth > 10 {
		return value
	}
	for token, original := range snapshot {
		if strings.Contains(value, token) {
			value = strings.ReplaceAll(value, token, expandValue(original, snapshot, depth+1))
		}
	}
	return value
}

// Clear wipes the in-memory mapping table and seen set. Persistent store
// entries are untouched — call after a request completes only when the
// redactor is not session-scoped.
func (r *Redactor) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mapping = make(map[string]string)
	r.reverse = make(map[string]string)
	r.counters = make(map[string]int64)
	r.seen = make(map[string]bool)
}

// MappingCount returns how many redactions are stored (for audit logging).
func (r *Redactor) MappingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.mapping)
}

// allocateToken creates a unique token for a matched value and stores the mapping.
// Token format: [TG:CATEGORY:N] — e.g. [TG:IP:1], [TG:EMAIL:2]
// Uses a reverse map for O(1) dedup instead of O(n) linear scan. With a
// store attached the token is stable for the lifetime of the session.
func (r *Redactor) allocateToken(p *Pattern, original string) string {
	return r.allocateCategory(p.Category, original)
}

func (r *Redactor) allocateCategory(category, original string) string {
	// O(1) dedup check: same value → same token, even across patterns.
	if token, ok := r.reverse[original]; ok {
		r.seen[token] = true
		return token
	}

	if category == "" {
		category = "REDACTED"
	}

	// Session-scoped store first: the store owns the numbering, so a value
	// seen in an earlier turn gets the token it already had.
	var token string
	if r.store != nil && r.session != "" {
		t, err := r.store.Token(r.session, category, original)
		if err == nil {
			token = t
		} else {
			// Do NOT fall back to in-memory numbering: it would re-issue
			// [TG:CAT:1] for a different value and corrupt the restore of
			// history tokens. A random, non-restorable token keeps the
			// content redacted and cannot collide.
			log.Printf("redact: token store unavailable, using non-restorable token: %v", err)
			token = randomToken(category)
		}
	}

	if token == "" {
		// No store: per-request numbering (stateless mode). The suffix is a
		// fixed marker, not a secret: the mapping exists only for this one
		// request, so a guessed token can never resolve anything.
		for {
			n := r.counters[category] + 1
			r.counters[category] = n
			candidate := fmt.Sprintf("[TG:%s:%d:%s]", category, n, StatelessTokenSuffix)
			if _, exists := r.mapping[candidate]; !exists {
				token = candidate
				break
			}
		}
	}

	r.mapping[token] = original
	r.reverse[original] = token
	r.seen[token] = true
	return token
}

// Summary maps pattern name → count of redactions.
type Summary map[string]int

// Total returns the total number of redactions across all patterns.
func (s Summary) Total() int {
	total := 0
	for _, count := range s {
		total += count
	}
	return total
}
