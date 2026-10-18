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
	"crypto/hmac"
	"crypto/rand"
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

	mu     sync.Mutex // serializes allocate/read-modify-write sequences
	now    func() time.Time
	secret []byte // per-vault HMAC key for unguessable tokens

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
	if err := v.loadOrCreateSecret(); err != nil {
		db.Close()
		return nil, err
	}
	// WAL sidecars hold the same plaintext; SQLite creates them 0644.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0600); err == nil {
			// exists and secured
		}
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
		`CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS session_owners (
			id       TEXT PRIMARY KEY,
			identity TEXT NOT NULL,
			updated  INTEGER NOT NULL,
			expires  INTEGER NOT NULL
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

// loadOrCreateSecret generates the per-vault HMAC key used to make tokens
// unguessable. The key lives in the vault DB, which is owner-only; a token
// without a valid suffix is never resolvable, so a guessed [TG:IP:1] is inert.
func (v *Vault) loadOrCreateSecret() error {
	var secret []byte
	err := v.db.QueryRow(`SELECT value FROM meta WHERE key = 'token_secret'`).Scan(&secret)
	if err == sql.ErrNoRows {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("vault secret: %w", err)
		}
		if _, err := v.db.Exec(`INSERT INTO meta (key, value) VALUES ('token_secret', ?)`, secret); err != nil {
			return fmt.Errorf("vault secret write: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("vault secret read: %w", err)
	}
	if len(secret) < 16 {
		return fmt.Errorf("vault secret too short (%d bytes)", len(secret))
	}
	v.secret = secret
	return nil
}

// tokenMAC returns the 8-hex-char suffix binding a token to its session,
// category, sequence and original value.
func (v *Vault) tokenMAC(session, category string, seq int64, original string) string {
	mac := hmac.New(sha256.New, v.secret)
	fmt.Fprintf(mac, "%s|%s|%d|%s", session, category, seq, original)
	return hex.EncodeToString(mac.Sum(nil))[:8]
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
		`SELECT token FROM tokens WHERE session = ? AND category = ? AND original = ? AND expires >= ?`,
		session, category, original, now.Unix(),
	).Scan(&token)
	if err == nil {
		_, _ = v.db.Exec(`UPDATE tokens SET last_used = ? WHERE session = ? AND token = ?`, now.Unix(), session, token)
		return token, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("vault lookup: %w", err)
	}
	// An expired row must not be re-issued: drop it so the value gets a fresh
	// token and expiry instead of an unusable one.
	if _, err := v.db.Exec(`DELETE FROM tokens WHERE session = ? AND category = ? AND original = ?`, session, category, original); err != nil {
		return "", fmt.Errorf("vault expired cleanup: %w", err)
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

	token = fmt.Sprintf("[TG:%s:%d:%s]", category, seq, v.tokenMAC(session, category, seq, original))
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

// ClaimSession records that identity owns session. Sessions are only
// adoptable — and tokens only resolvable — by the identity that created them.
func (v *Vault) ClaimSession(session, identity string) error {
	if session == "" {
		return nil
	}
	if identity == "" {
		identity = "local"
	}
	now := v.now()
	_, err := v.db.Exec(
		`INSERT INTO session_owners (id, identity, updated, expires) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET identity = excluded.identity,
		 updated = excluded.updated, expires = excluded.expires`,
		session, identity, now.Unix(), now.Add(v.ttl*7).Unix(),
	)
	if err != nil {
		return fmt.Errorf("vault session claim: %w", err)
	}
	return nil
}

// SessionOwnedBy reports whether identity owns session.
func (v *Vault) SessionOwnedBy(session, identity string) bool {
	if session == "" {
		return false
	}
	if identity == "" {
		identity = "local"
	}
	var owner string
	var expires int64
	err := v.db.QueryRow(
		`SELECT identity, expires FROM session_owners WHERE id = ?`, session,
	).Scan(&owner, &expires)
	if err != nil || expires < v.now().Unix() {
		return false
	}
	return owner == identity
}

// SessionsForTokensOwnedBy returns the sessions that own any of the given
// tokens AND belong to identity. Tokens are guessable labels, so ownership is
// the only thing that makes adoption safe.
func (v *Vault) SessionsForTokensOwnedBy(tokens []string, identity string) ([]string, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	if identity == "" {
		identity = "local"
	}
	placeholders := make([]string, len(tokens))
	args := make([]interface{}, 0, len(tokens)+2)
	for i, t := range tokens {
		placeholders[i] = "?"
		args = append(args, t)
	}
	args = append(args, identity, v.now().Unix())
	q := `SELECT DISTINCT t.session FROM tokens t
	      JOIN session_owners o ON o.id = t.session
	      WHERE t.token IN (` + strings.Join(placeholders, ",") + `)
	        AND o.identity = ? AND o.expires >= ? AND t.expires >= ?`
	args = append(args, v.now().Unix())
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
		`DELETE FROM session_owners WHERE expires < ?`,
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

// tokenRe matches the canonical Tidegate token shape, including the
// session-bound MAC suffix ([TG:IP:1:9f3c1a2b]).
var tokenRe = regexp.MustCompile(`\[TG:[A-Z0-9_]+:[0-9]+:[0-9a-f]{8}\]`)

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

// DeriveSession determines the session id for a request.
//
// identity must be the authenticated principal (gateway client-key name, or
// "local" in single-machine mode) — never a spoofable header value. Tokens are
// readable labels like [TG:IP:1], so a token must not function as a bearer
// capability: adoption and restore are both bound to the identity that
// created the session.
//
// Order:
//  1. X-Tidegate-Session header, hashed together with the identity.
//  2. Tokens in the request owned by exactly one session of this identity.
//  3. Fingerprint of the conversation opening (identity + system + first user).
//  4. "" for stateless requests (per-request mappings).
func DeriveSession(header, identity string, body []byte, v *Vault) string {
	if identity == "" {
		identity = "local"
	}
	if h := strings.TrimSpace(header); h != "" {
		sum := sha256.Sum256([]byte(identity + "\x00" + h))
		return "h:" + hex.EncodeToString(sum[:8])
	}

	rawTokens := TokensIn(string(body))
	if v != nil && len(rawTokens) > 0 {
		if len(rawTokens) > 16 {
			rawTokens = rawTokens[:16]
		}
		if sessions, err := v.SessionsForTokensOwnedBy(rawTokens, identity); err == nil && len(sessions) == 1 {
			return sessions[0]
		}
	}

	prefix := conversationPrefix(body)
	if prefix == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(identity + "\x00" + prefix))
	return "f:" + hex.EncodeToString(sum[:8])
}

// DeriveAndClaim derives the session and records identity ownership. Use this
// from request paths; DeriveSession is the pure variant for tests.
func DeriveAndClaim(header, identity string, body []byte, v *Vault) string {
	session := DeriveSession(header, identity, body, v)
	if v != nil && session != "" {
		_ = v.ClaimSession(session, identity)
	}
	return session
}

// conversationPrefix extracts the stable opening of a conversation: the first
// system message plus the first non-system message. Both stay byte-identical
// as the conversation grows, which is what makes the fingerprint stable.
func conversationPrefix(body []byte) string {
	var req struct {
		System   interface{}   `json:"system"`
		Messages []interface{} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Messages) == 0 {
		return ""
	}
	// Anthropic carries the system prompt outside messages; including it
	// keeps conversations with different system prompts in separate sessions.
	if sys := contentString(req.System); sys != "" {
		if len(sys) > 4096 {
			sys = sys[:4096]
		}
		req.Messages = append([]interface{}{map[string]interface{}{"role": "system", "content": sys}}, req.Messages...)
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
