// Package route implements the routing logic for the Tidegate gateway.
// It decides where content goes: cloud API (scrubbed), local Ollama (full data),
// or blocked entirely. It coordinates the classifier, redactor, and Ollama client.
package route

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/qo-roj/tidegate/internal/audit"
	"github.com/qo-roj/tidegate/internal/classify"
	"github.com/qo-roj/tidegate/internal/content"
	"github.com/qo-roj/tidegate/internal/ollama"
	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/rules"
	"github.com/qo-roj/tidegate/internal/vault"
)

// RequestContext holds per-request state (primarily the redactor mapping)
// that must be shared between ProcessRequest and the corresponding
// ProcessResponse/ProcessStreamChunk. This prevents concurrent requests
// from cross-contaminating each other's token mappings.
type RequestContext struct {
	Redactor *redact.Redactor
	// Session is the conversation identity used for the token vault.
	Session string
	// Summary counts redactions by pattern (plus json_secret for
	// structure-aware redaction).
	Summary redact.Summary
	// Tiers counts classified blocks by tier.
	Tiers map[string]int
	// CacheHits counts blocks served from the content-addressed
	// redaction cache instead of being re-scanned.
	CacheHits int
}

// Router coordinates the classification, redaction, and routing of content.
type Router struct {
	Classifier *classify.Classifier
	Ollama     *ollama.Client
	AuditLog   *audit.Log
	RuleSet    *rules.RuleSet // kept for pattern-toggle consultation

	// Vault, when set, makes token mappings session-scoped and persistent
	// and enables delta-only processing.
	Vault *vault.Vault

	// enabledPatterns is the resolved [redaction.patterns] set (nil → all
	// default patterns, matching pre-toggle behavior).
	enabledPatterns []string

	// rulesetFingerprint identifies the active pattern set in the
	// redaction cache, so a config change never reuses stale output.
	rulesetFingerprint string
}

// New creates a Router with all dependencies wired.
func New(rs *rules.RuleSet, ollamaClient *ollama.Client, auditLog *audit.Log) *Router {
	r := &Router{
		Classifier: classify.New(rs),
		Ollama:     ollamaClient,
		AuditLog:   auditLog,
		RuleSet:    rs,
	}
	// Resolve pattern toggles once at startup. A pattern redacts when:
	//   - it is a default pattern and not explicitly disabled, or
	//   - it is an extended pattern explicitly enabled by any layer.
	// Extended patterns stay opt-in — an unmentioned toggle must not turn
	// on aggressive patterns (e.g. high_entropy_secret) by accident.
	if rs != nil {
		for _, name := range redact.PatternNames() {
			if !rs.IsRedactionEnabled(name) {
				continue // explicitly disabled in the highest layer
			}
			if _, explicit := rs.RedactionFlags[name]; explicit || redact.IsDefaultPattern(name) {
				r.enabledPatterns = append(r.enabledPatterns, name)
			}
		}
	}
	r.rulesetFingerprint = ruleFingerprint(r.enabledPatterns)
	return r
}

// ruleFingerprint hashes the active rule set. Bump redactionAlgoVersion when
// the redaction algorithm changes in a way that alters output.
func ruleFingerprint(patterns []string) string {
	names := append([]string{}, patterns...)
	sort.Strings(names)
	sum := sha256.Sum256([]byte("redaction-v2\x00" + strings.Join(names, ",")))
	return hex.EncodeToString(sum[:8])
}

// WithVault attaches a session vault. Returns the router for chaining.
func (r *Router) WithVault(v *vault.Vault) *Router {
	r.Vault = v
	return r
}

// newRedactor builds the per-request Redactor honoring pattern toggles.
func (r *Router) newRedactor() *redact.Redactor {
	if r.enabledPatterns == nil {
		return redact.New()
	}
	return redact.NewWithNames(r.enabledPatterns)
}

// NewRedactor returns a fresh Redactor honoring the configured pattern
// toggles. Exposed for the dry-run CLI command and tests.
func (r *Router) NewRedactor() *redact.Redactor {
	return r.newRedactor()
}

// ProcessRequest takes an incoming LLM API request body, classifies each
// content block, and returns the modified request body ready to forward
// to the cloud API. For local-only blocks, the content is sent to Ollama
// and replaced with a de-identified summary.
//
// This is the stateless entry point. Callers that can identify a conversation
// should use ProcessRequestSession so tokens stay stable across turns.
func (r *Router) ProcessRequest(body []byte, agent string, provider string) (ctx *RequestContext, modifiedBody []byte, blocked bool, err error) {
	return r.ProcessRequestSession(body, agent, provider, "")
}

// ProcessRequestSession is ProcessRequest with an explicit conversation
// session. With a vault attached, only messages added since the last request
// in the same session are classified and redacted; earlier messages are
// forwarded byte-for-byte, which keeps provider prompt caches warm and avoids
// re-tokenising history.
func (r *Router) ProcessRequestSession(body []byte, agent string, provider, session string) (ctx *RequestContext, modifiedBody []byte, blocked bool, err error) {
	// Parse as generic JSON for modification
	var request map[string]interface{}
	if err := json.Unmarshal(body, &request); err != nil {
		return &RequestContext{Redactor: r.newRedactor(), Summary: redact.Summary{}}, body, false, nil // unparseable — pass through
	}

	rawMessages, ok := request["messages"].([]interface{})
	if !ok {
		return &RequestContext{Redactor: r.newRedactor(), Summary: redact.Summary{}}, body, false, nil
	}

	blocks := classify.ParseRequest(body)
	if len(blocks) == 0 {
		// Can't parse — let it through as-is (better than blocking)
		return &RequestContext{Redactor: r.newRedactor(), Summary: redact.Summary{}}, body, false, nil
	}

	// Align message objects with content blocks. Both walks skip non-object
	// messages, so the i-th pair is always the i-th message.
	pairs := make([]messagePair, 0, len(rawMessages))
	bi := 0
	for _, raw := range rawMessages {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if bi >= len(blocks) {
			break
		}
		pairs = append(pairs, messagePair{msg: m, block: blocks[bi]})
		bi++
	}
	if len(pairs) == 0 {
		return &RequestContext{Redactor: r.newRedactor(), Summary: redact.Summary{}}, body, false, nil
	}

	// Session-scoped Redactor — keeps concurrency isolation and, when a
	// vault is configured, stable tokens across turns.
	reqRedactor := r.newRedactor()
	if r.Vault != nil && session != "" {
		reqRedactor.WithStore(r.Vault, session)
	}
	ctx = &RequestContext{
		Redactor: reqRedactor,
		Session:  session,
		Summary:  redact.Summary{},
		Tiers:    map[string]int{},
	}

	// Record tokens present anywhere in the incoming request (history
	// included) so the response can resolve them — and only them.
	for _, p := range pairs {
		reqRedactor.NoteTokens(p.block.Content)
	}

	anyBlocked := false

	for _, p := range pairs {
		block := p.block
		m := p.msg
		result := r.Classifier.ClassifyBlock(block, agent)
		ctx.Tiers[result.Tier.String()]++

		switch result.Tier {
		case rules.TierBlocked:
			anyBlocked = true
			if r.AuditLog != nil {
				r.AuditLog.Record(audit.Entry{
					Agent:    agent,
					Provider: provider,
					Action:   "read",
					Target:   block.FilePath,
					Tier:     "blocked",
					Notes:    "blocked by rule: " + result.Source,
				})
			}
			// Replace content with block message
			setMessageContent(m, "[Tidegate: access denied — content blocked]")

		case rules.TierLocalOnly:
			// Send to Ollama for summarization
			if r.Ollama != nil && r.Ollama.Available() {
				summary, err := r.Ollama.Summarize(block.Content, r.enabledPatterns)
				if err != nil {
					// Ollama failed — block the content
					setMessageContent(m, "[Tidegate: local-only content could not be processed]")
					if r.AuditLog != nil {
						r.AuditLog.Record(audit.Entry{
							Agent:    agent,
							Provider: provider,
							Action:   "read",
							Target:   block.FilePath,
							Tier:     "local-only",
							Notes:    "ollama failed: " + err.Error(),
						})
					}
				} else {
					setMessageContent(m, "[Ollama summary: "+summary+"]")
					if r.AuditLog != nil {
						r.AuditLog.Record(audit.Entry{
							Agent:    agent,
							Provider: provider,
							Action:   "read",
							Target:   block.FilePath,
							Tier:     "local-only",
							Notes:    "summarized by Ollama",
						})
					}
				}
			} else {
				// No Ollama — block
				setMessageContent(m, "[Tidegate: local-only content blocked — Ollama not available]")
				if r.AuditLog != nil {
					r.AuditLog.Record(audit.Entry{
						Agent:    agent,
						Provider: provider,
						Action:   "read",
						Target:   block.FilePath,
						Tier:     "blocked",
						Notes:    "ollama unavailable",
					})
				}
			}

		case rules.TierRedacted:
			// Content-shape-aware redaction: JSON sensitive keys first,
			// then patterns over timestamp-shielded text.
			content := getBlockContent(m)
			redacted, summary := r.redactContent(ctx, reqRedactor, content)
			setMessageContent(m, redacted)
			for k, v := range summary {
				ctx.Summary[k] += v
			}
			if r.AuditLog != nil {
				redactionsJSON, _ := json.Marshal(summary)
				r.AuditLog.Record(audit.Entry{
					Agent:      agent,
					Provider:   provider,
					Action:     "read",
					Target:     block.FilePath,
					Tier:       "redacted",
					Redactions: string(redactionsJSON),
				})
			}

		case rules.TierPublic:
			// Pass through as-is
			if r.AuditLog != nil {
				r.AuditLog.Record(audit.Entry{
					Agent:    agent,
					Provider: provider,
					Action:   "read",
					Target:   block.FilePath,
					Tier:     "public",
				})
			}
		}
	}

	// Serialize the modified request
	modified, err := json.Marshal(request)
	if err != nil {
		// Serialization failed — return error so the proxy can block
		return ctx, nil, anyBlocked, fmt.Errorf("marshaling modified request: %w", err)
	}

	return ctx, modified, anyBlocked, nil
}

// ApplyShapeRedaction applies Tidegate's shape-aware redaction to one block:
// JSON sensitive keys first, then patterns over timestamp-shielded text.
// Exported so one-off surfaces (tidegate text) share the proxy's behaviour.
func ApplyShapeRedaction(src string, reqRedactor *redact.Redactor) (string, redact.Summary) {
	summary := redact.Summary{}

	shielded, restore := content.ShieldTimestamps(src)

	if content.Detect(src) == content.KindJSON {
		var n int
		shielded, n = content.RedactJSONKeys(shielded, func(key, value string) string {
			return reqRedactor.Allocate("SECRET", value)
		})
		if n > 0 {
			summary["json_secret"] = n
		}
	}

	redacted, patternSummary := reqRedactor.Redact(shielded)
	for k, v := range patternSummary {
		summary[k] += v
	}
	return restore(redacted), summary
}

// redactContent applies shape-aware redaction with the content-addressed
// cache in front of it.
func (r *Router) redactContent(ctx *RequestContext, reqRedactor *redact.Redactor, src string) (string, redact.Summary) {
	var cacheKey string
	if r.Vault != nil && ctx.Session != "" {
		sum := sha256.Sum256([]byte(src))
		cacheKey = hex.EncodeToString(sum[:])
		if redacted, sumJSON, ok, err := r.Vault.CachedRedaction(ctx.Session, r.rulesetFingerprint, cacheKey); err == nil && ok {
			summary := redact.Summary{}
			if err := json.Unmarshal([]byte(sumJSON), &summary); err == nil {
				// The cached output still carries tokens from this
				// session; mark them seen so responses can resolve them.
				reqRedactor.NoteTokens(redacted)
				ctx.CacheHits++
				return redacted, summary
			}
		}
	}

	out, summary := ApplyShapeRedaction(src, reqRedactor)

	if r.Vault != nil && ctx.Session != "" && cacheKey != "" {
		if sumJSON, err := json.Marshal(summary); err == nil {
			_ = r.Vault.StoreRedaction(ctx.Session, r.rulesetFingerprint, cacheKey, out, string(sumJSON))
		}
	}
	return out, summary
}

// messagePair keeps a request message aligned with its extracted content
// block.
type messagePair struct {
	msg   map[string]interface{}
	block classify.ContentBlock
}

// ProcessResponse reverse-maps redaction tokens in the cloud model's response.
// This lets the agent see real values in the response instead of [TG:IP:1] tokens.
// ctx carries the per-request redactor mapping from ProcessRequest.
func (r *Router) ProcessResponse(ctx *RequestContext, body []byte) []byte {
	if ctx == nil || ctx.Redactor == nil {
		return body
	}
	tm := redact.NewTokenMatcher(ctx.Redactor)
	if !tm.HasMappings() {
		return body
	}

	// Try to parse as JSON and reverse-map string values
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		// Not JSON — try plain text
		return []byte(tm.Restore(string(body)))
	}

	restoreInPlace(response, tm)

	modified, err := json.Marshal(response)
	if err != nil {
		return body
	}
	return modified
}

// ProcessStreamChunk processes a single SSE streaming chunk from the cloud API.
// It reverse-maps any tokens that appear in the chunk, handling split tokens
// with a boundary buffer. The StreamRedactor is per-response — the caller
// should create one and reuse it across all chunks for a given response.
func (r *Router) ProcessStreamChunk(ctx *RequestContext, sr *redact.StreamRedactor, chunk []byte) []byte {
	if ctx == nil || ctx.Redactor == nil || sr == nil {
		return chunk
	}
	return sr.ProcessChunk(chunk)
}

// NewStreamRedactor creates a StreamRedactor for a streaming response,
// using the per-request redactor mapping. Call once per response and reuse
// across all chunks.
func (r *Router) NewStreamRedactor(ctx *RequestContext) *redact.StreamRedactor {
	if ctx == nil || ctx.Redactor == nil {
		return nil
	}
	tm := redact.NewTokenMatcher(ctx.Redactor)
	if !tm.HasMappings() {
		return nil
	}
	return redact.NewStreamRedactor(tm)
}

// setMessageContent sets the content of a message in a JSON message object.
func setMessageContent(m map[string]interface{}, content string) {
	m["content"] = content
}

// getBlockContent extracts the string content from a message.
func getBlockContent(m map[string]interface{}) string {
	if content, ok := m["content"].(string); ok {
		return content
	}
	// Array content (Anthropic)
	if content, ok := m["content"].([]interface{}); ok {
		var result string
		for _, part := range content {
			if p, ok := part.(map[string]interface{}); ok {
				if text, ok := p["text"].(string); ok {
					result += text + "\n"
				}
			}
		}
		return result
	}
	return ""
}

// restoreInPlace recursively walks a JSON structure and restores tokens in strings.
func restoreInPlace(v interface{}, tm *redact.TokenMatcher) {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if s, ok := v.(string); ok {
				val[k] = tm.Restore(s)
			} else {
				restoreInPlace(v, tm)
			}
		}
	case []interface{}:
		for i, v := range val {
			if s, ok := v.(string); ok {
				val[i] = tm.Restore(s)
			} else {
				restoreInPlace(v, tm)
			}
		}
	}
}
