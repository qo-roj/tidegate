// Package vault implements Tidegate's session-scoped token vault.
//
// Token mappings are persisted in SQLite and scoped to a conversation
// session instead of a single request. That fixes two problems with the
// original per-request mappings:
//
//  1. Correctness — token numbering restarted at [TG:IP:1] on every request,
//     so a token echoed from conversation history could be reverse-mapped to
//     a *different* secret in the same turn.
//  2. Continuity — tokens in history stay resolvable across turns, so the
//     model can refer back to a redacted value and get the real value back.
//
// The vault stores originals locally only. It never logs them, and entries
// expire (default 24h) so a stolen database has a bounded useful lifetime.
package vault

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DefaultTTL is how long a token mapping stays resolvable.
const DefaultTTL = 24 * time.Hour

// Vault is a persistent, session-scoped token store.
type Vault struct {
	db  *sql.DB
	ttl time.Duration

	mu  sync.Mutex // serializes allocate/read-modify-write sequences
	now func() time.Time

	stop chan struct{}
	wg   sync.WaitGroup
}

// Open opens (or creates) the vault at path and starts the expiry sweeper.
func Open(path string, ttl time.Duration) (*Vault, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening vault: %w", err)
	}
	// SQLite handles concurrent writes poorly; one connection keeps
	// transactions predictable and avoids SQLITE_BUSY storms.
	db.SetMaxOpenConns(1)

	v := &Vault{db: db, ttl: ttl, now: time.Now, stop: make(chan struct{})}
	if err := v.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// The vault holds originals — keep it owner-only regardless of umask.
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("securing vault file: %w", err)
	}

	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := v.Sweep(); err != nil {
					// Sweeping is best-effort; a full disk or locked DB must
					// not take the gateway down.
					log.Printf("vault: sweep failed: %v", err)
				}
			case <-v.stop:
				return
			}
		}
	}()

	return v, nil
}

func (v *Vault) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tokens (
			session   TEXT NOT NULL,
			token     TEXT NOT NULL,
			category  TEXT NOT NULL,
			original  TEXT NOT NULL,
			created   INTEGER NOT NULL,
			expires   INTEGER NOT NULL,
			last_used INTEGER NOT NULL,
			PRIMARY KEY (session, token)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_original ON tokens(session, category, original)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)`,
		`CREATE TABLE IF NOT EXISTS counters (
			session  TEXT NOT NULL,
			category TEXT NOT NULL,
			seq      INTEGER NOT NULL,
			PRIMARY KEY (session, category)
		)`,
		`CREATE TABLE IF NOT EXISTS redaction_cache (
			session  TEXT NOT NULL,
			ruleset  TEXT NOT NULL,
			hash     TEXT NOT NULL,
			redacted TEXT NOT NULL,
			summary  TEXT NOT NULL,
			expires  INTEGER NOT NULL,
			PRIMARY KEY (session, ruleset, hash)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_expires ON redaction_cache(expires)`,
	}
	for _, s := range stmts {
		if _, err := v.db.Exec(s); err != nil {
			return fmt.Errorf("vault migration: %w", err)
		}
	}
	return nil
}

// Close stops the sweeper and closes the database.
func (v *Vault) Close() error {
	select {
	case <-v.stop:
	default:
		close(v.stop)
	}
	v.wg.Wait()
	return v.db.Close()
}

// normalizeCategory turns an arbitrary label into a token-safe category.
func normalizeCategory(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	var b strings.Builder
	for _, r := range c {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "REDACTED"
	}
	return b.String()
}

// Token returns the stable token for original within session. The same value
// in the same session always yields the same token; a different session gets
// its own numbering, so sessions cannot collide or resolve each other's values.
func (v *Vault) Token(session, category, original string) (string, error) {
	if session == "" {
		return "", fmt.Errorf("vault: empty session")
	}
	category = normalizeCategory(category)
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	var token string
	err := v.db.QueryRow(
		`SELECT token FROM tokens WHERE session = ? AND category = ? AND original = ?`,
		session, category, original,
	).Scan(&token)
	if err == nil {
		_, _ = v.db.Exec(`UPDATE tokens SET last_used = ? WHERE session = ? AND token = ?`, now.Unix(), session, token)
		return token, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("vault lookup: %w", err)
	}

	tx, err := v.db.Begin()
	if err != nil {
		return "", fmt.Errorf("vault begin: %w", err)
	}
	defer tx.Rollback()

	var seq int64
	err = tx.QueryRow(`SELECT seq FROM counters WHERE session = ? AND category = ?`, session, category).Scan(&seq)
	switch {
	case err == sql.ErrNoRows:
		seq = 1
		if _, err := tx.Exec(`INSERT INTO counters (session, category, seq) VALUES (?, ?, ?)`, session, category, seq); err != nil {
			return "", fmt.Errorf("vault counter: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("vault counter read: %w", err)
	default:
		seq++
		if _, err := tx.Exec(`UPDATE counters SET seq = ? WHERE session = ? AND category = ?`, seq, session, category); err != nil {
			return "", fmt.Errorf("vault counter update: %w", err)
		}
	}

	token = fmt.Sprintf("[TG:%s:%d]", category, seq)
	if _, err := tx.Exec(
		`INSERT INTO tokens (session, token, category, original, created, expires, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		session, token, category, original, now.Unix(), now.Add(v.ttl).Unix(), now.Unix(),
	); err != nil {
		return "", fmt.Errorf("vault insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("vault commit: %w", err)
	}
	return token, nil
}

// Lookup resolves a token inside a session. Expired entries are treated as
// missing (and left for the sweeper to delete).
func (v *Vault) Lookup(session, token string) (string, bool, error) {
	if session == "" {
		return "", false, nil
	}
	var original string
	var expires int64
	err := v.db.QueryRow(
		`SELECT original, expires FROM tokens WHERE session = ? AND token = ?`,
		session, token,
	).Scan(&original, &expires)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("vault lookup: %w", err)
	}
	if expires < v.now().Unix() {
		return "", false, nil
	}
	return original, true, nil
}

// Tokens returns every live token mapping for a session.
func (v *Vault) Tokens(session string) (map[string]string, error) {
	out := map[string]string{}
	if session == "" {
		return out, nil
	}
	rows, err := v.db.Query(
		`SELECT token, original FROM tokens WHERE session = ? AND expires >= ?`,
		session, v.now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("vault tokens: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var token, original string
		if err := rows.Scan(&token, &original); err != nil {
			return nil, err
		}
		out[token] = original
	}
	return out, rows.Err()
}

// SessionsForTokens returns the distinct sessions that own any of the given
// tokens. Used to follow a conversation's lineage when the client does not
// send an explicit session header.
func (v *Vault) SessionsForTokens(tokens []string) ([]string, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(tokens))
	args := make([]interface{}, len(tokens))
	for i, t := range tokens {
		placeholders[i] = "?"
		args[i] = t
	}
	q := `SELECT DISTINCT session FROM tokens WHERE token IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := v.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("vault session lookup: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Sweep deletes expired tokens and cached redactions.
func (v *Vault) Sweep() (int64, error) {
	now := v.now().Unix()
	var total int64
	for _, q := range []string{
		`DELETE FROM tokens WHERE expires < ?`,
		`DELETE FROM redaction_cache WHERE expires < ?`,
	} {
		res, err := v.db.Exec(q, now)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// Stats returns live token and cache-entry counts.
func (v *Vault) Stats() (tokens int64, cached int64, err error) {
	now := v.now().Unix()
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE expires >= ?`, now).Scan(&tokens); err != nil {
		return 0, 0, err
	}
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM redaction_cache WHERE expires >= ?`, now).Scan(&cached); err != nil {
		return tokens, 0, err
	}
	return tokens, cached, nil
}

// CachedRedaction returns a previously redacted form of content for a
// session, keyed by content hash and rule-set fingerprint. Redaction is
// deterministic within a session, so a hit is always equivalent to
// recomputing it.
func (v *Vault) CachedRedaction(session, ruleset, hash string) (redacted, summary string, ok bool, err error) {
	if session == "" {
		return "", "", false, nil
	}
	var expires int64
	err = v.db.QueryRow(
		`SELECT redacted, summary, expires FROM redaction_cache WHERE session = ? AND ruleset = ? AND hash = ?`,
		session, ruleset, hash,
	).Scan(&redacted, &summary, &expires)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("vault cache read: %w", err)
	}
	if expires < v.now().Unix() {
		return "", "", false, nil
	}
	return redacted, summary, true, nil
}

// StoreRedaction caches a redacted block.
func (v *Vault) StoreRedaction(session, ruleset, hash, redacted, summary string) error {
	if session == "" {
		return nil
	}
	now := v.now()
	_, err := v.db.Exec(
		`INSERT INTO redaction_cache (session, ruleset, hash, redacted, summary, expires)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(session, ruleset, hash) DO UPDATE SET redacted = excluded.redacted,
		 summary = excluded.summary, expires = excluded.expires`,
		session, ruleset, hash, redacted, summary, now.Add(v.ttl).Unix(),
	)
	if err != nil {
		return fmt.Errorf("vault cache write: %w", err)
	}
	return nil
}

// tokenRe matches the canonical Tidegate token shape.
var tokenRe = regexp.MustCompile(`\[TG:[A-Z0-9_]+:[0-9]+\]`)

// TokensIn extracts every Tidegate token appearing in content.
func TokensIn(content string) []string {
	matches := tokenRe.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// DeriveSession determines the session id for a request:
//
//  1. An explicit X-Tidegate-Session header wins (hashed, so the header value
//     itself is not persisted).
//  2. Otherwise, if the request carries tokens owned by exactly one known
//     session, that session is adopted — the conversation identifies itself.
//  3. Otherwise, a fingerprint of the stable conversation prefix (agent +
//     first system message + first user message) is used.
//  4. Stateless requests (no messages) get "" and fall back to per-request
//     mappings.
func DeriveSession(header, agent string, body []byte, v *Vault) string {
	if h := strings.TrimSpace(header); h != "" {
		sum := sha256.Sum256([]byte(h))
		return "h:" + hex.EncodeToString(sum[:8])
	}

	rawTokens := TokensIn(string(body))
	if v != nil && len(rawTokens) > 0 {
		if len(rawTokens) > 16 {
			rawTokens = rawTokens[:16]
		}
		if sessions, err := v.SessionsForTokens(rawTokens); err == nil && len(sessions) == 1 {
			return sessions[0]
		}
	}

	prefix := conversationPrefix(body)
	if prefix == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(agent + "\x00" + prefix))
	return "f:" + hex.EncodeToString(sum[:8])
}

// conversationPrefix extracts the stable opening of a conversation: the first
// system message plus the first non-system message. Both stay byte-identical
// as the conversation grows, which is what makes the fingerprint stable.
func conversationPrefix(body []byte) string {
	var req struct {
		Messages []interface{} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Messages) == 0 {
		return ""
	}
	firstSystem := ""
	firstOther := ""
	for _, raw := range req.Messages {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		text := contentString(m["content"])
		if text == "" {
			continue
		}
		if role == "system" && firstSystem == "" {
			firstSystem = text
		}
		if role != "system" && firstOther == "" {
			firstOther = text
		}
		if firstOther != "" {
			break
		}
	}
	if firstSystem == "" && firstOther == "" {
		return ""
	}
	// Bound the fingerprint input so a huge opening prompt does not cost
	// more than hashing it.
	if len(firstSystem) > 4096 {
		firstSystem = firstSystem[:4096]
	}
	if len(firstOther) > 4096 {
		firstOther = firstOther[:4096]
	}
	return firstSystem + "\x00" + firstOther
}

func contentString(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		var b strings.Builder
		for _, part := range c {
			p, ok := part.(map[string]interface{})
			if !ok {
				continue
			}
			if t, ok := p["text"].(string); ok {
				b.WriteString(t)
			}
		}
		return b.String()
	}
	return ""
}
