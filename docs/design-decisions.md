# Tidegate — Design Decisions

Resolving the 9 issues raised in the architecture review.

---

## Issue 1: Mixed-Tier Content in Single Requests

### Problem

A single agent request often contains content at multiple classification tiers. For
example, an agent reading `/etc/nginx/nginx.conf` might produce a request containing:
- The nginx config (redacted — has internal IPs)
- A reference to `/etc/letsencrypt/live/myapp.com/privkey.pem` (local-only — SSL key path)
- The agent's own reasoning text (public)

The original architecture assigned one tier per request. That doesn't work when a
single request spans multiple tiers.

### Decision: Content-Block-Level Classification

Classification operates on **content blocks**, not whole requests. LLM API requests
are structured — they contain messages, and messages contain content blocks (text,
tool results, file contents). Tidegate parses the API request structure and
classifies each content block independently.

```
Request:
  messages:
    [0] role: system, content: "You are a coding agent..."     → PUBLIC
    [1] role: user, content: "Here's my nginx config:\n<file>"  → REDACTED (path match)
         └─ embedded file content contains:
            ├─ "server_name myapp.com;"                         → public (hostname, not PII)
            ├─ "proxy_pass http://10.0.0.5:8080;"               → REDACTED (private IP)
            └─ "ssl_certificate_key /etc/letsencrypt/..."        → LOCAL-ONLY (letsencrypt path)
    [2] role: user, content: "Also check ~/.zsh_history"       → REDACTED (shell history)
```

### Implementation: Tier Escalation Within Blocks

When a single content block contains multiple sub-tier elements, the block is
escalated to the **highest** tier present:

| Block contains... | Block tier |
|---|---|
| Only public content | `public` |
| Public + redacted patterns | `redacted` (patterns stripped, forwarded) |
| Public + redacted + local-only references | `local-only` (whole block → Ollama) |
| Any blocked content | `blocked` (whole block refused) |

This is conservative — when in doubt, escalate. A block with one local-only
reference goes entirely to Ollama rather than trying to split it mid-block.

### The Split: When to Fragment vs Escalate

Tidegate fragments at **natural boundaries** (message boundaries, tool-result
boundaries, file-content boundaries) and escalates within fragments:

```
Message [1] content: "Here's my nginx config:\n<file content with secrets>"

Tidegate detects this is a tool result containing a file read.
→ The file content is extracted as a sub-block
→ Sub-block classified: contains private IP + letsencrypt path → LOCAL-ONLY
→ Sub-block sent to Ollama for summarization
→ Summary replaces the file content in the message
→ Message [1] now reads: "Here's my nginx config:\n[Ollama summary: nginx configured with reverse proxy to internal service, SSL via Let's Encrypt]"
→ Rest of request proceeds normally
```

The key insight: agents structure their requests. They don't send arbitrary blobs —
they send messages with tool results, file reads, and reasoning. Tidegate parses
that structure and classifies at the boundary that makes sense.

---

## Issue 2: Streaming (SSE) Support

### Problem

LLM APIs use Server-Sent Events (SSE) for streaming responses. The proxy must
handle streaming without buffering entire responses (which would defeat the
purpose of streaming and add latency).

### Decision: Stream-Through with Reverse-Mapping Filter

Tidegate does NOT redact outbound streaming responses — the cloud model's
response tokens are not sensitive (they're generated text, not user data). The
streaming concern is **reverse-mapping**: if the cloud model mentions
`[IP_REDACTED_1]` in a streaming response, Tidegate must replace it with the
real IP in real-time.

```
Cloud SSE stream:
  data: {"content": "Check if "}
  data: {"content": "[IP_REDACTED_1]"}
  data: {"content": " is a known threat"}
  data: [DONE]

Tidegate reverse-mapping filter (streaming):
  data: {"content": "Check if "}
  data: {"content": "203.0.113.42"}        ← token replaced
  data: {"content": " is a known threat"}
  data: [DONE]
```

### Implementation: Token Boundary Buffer

Tokens like `[IP_REDACTED_1]` can be split across SSE chunks. Tidegate maintains
a small **token boundary buffer** (max 64 bytes) that holds the tail of each chunk.
If the buffer contains a partial token prefix (e.g. `[IP_REDACT`), Tidegate waits
for the next chunk before flushing. If the next chunk completes the token, it's
replaced. If it doesn't match, the buffer is flushed as-is.

```go
type StreamRedactor struct {
    mapping    map[string]string  // [IP_REDACTED_1] → 203.0.113.42
    buffer     []byte             // tail buffer for split tokens
    maxBuffer  int                // 64 bytes
    tokenRegex *regexp.Regexp     // matches [A-Z_]+_REDACTED_\d+
}

func (sr *StreamRedactor) ProcessChunk(chunk []byte) []byte {
    // Prepend buffer, scan for tokens, replace, keep tail in buffer
    combined := append(sr.buffer, chunk...)
    replaced := sr.tokenRegex.ReplaceAllStringFunc(string(combined), sr.replaceToken)
    // If the end of replaced could be a partial token, keep it in buffer
    flush, keep := sr.splitAtTokenBoundary(replaced)
    sr.buffer = keep
    return flush
}
```

### Inbound Streaming (Agent → Cloud)

Inbound requests are NOT streamed — agents send complete request bodies. The
streaming is only on the response side. So inbound redaction remains batch-mode.

If a future agent harness streams requests (unlikely but possible), Tidegate
will buffer the inbound stream, redact, then forward as a batch. The latency cost
is acceptable because request redaction is the critical security path.

---

## Issue 3: Token Reverse-Mapping Robustness

### Problem

The in-memory mapping (`[IP_REDACTED_1]` → `203.0.113.42`) works for exact matches
but fails when:
- The cloud model reformats the token (e.g., `[IP_REDACTED_1]` → `"IP_REDACTED_1"`)
- The token appears in code the model generates (e.g., `ip = "IP_REDACTED_1"`)
- The model partially quotes or references the token
- The model splits the token across lines

### Decision: Fuzzy Token Matching with Scoped Mappings

### Token Format

Tokens use a distinctive, unlikely-to-collide format:

```
[TG:IP:1]        → IP address #1
[TG:EMAIL:3]     → Email address #3
[TG:TOKEN:1]    → API token #1
[TG:KEY:1]      → Private key #1
```

The `TG:` prefix makes collisions with natural text extremely unlikely. The
category prefix enables targeted reverse-mapping.

### Matching Strategy

```go
type TokenMatcher struct {
    mappings map[string]string  // exact: "TG:IP:1" → "203.0.113.42"
    fuzzy    []FuzzyPattern     // patterns for reformatted tokens
}

type FuzzyPattern struct {
    regex    *regexp.Regexp
    category string
    captureGroup int
}

// Exact match (primary)
[TG:IP:1] → 203.0.113.42

// Fuzzy matches (fallback)
"TG:IP:1"     → 203.0.113.42    (quotes stripped)
TG:IP:1       → 203.0.113.42    (brackets stripped)
`TG:IP:1`     → 203.0.113.42    (backticks stripped)
TG_IP_1       → 203.0.113.42    (underscores substituted)
```

### Scoped Mappings

Each request gets its own mapping scope. Mappings are NOT shared across requests
(even from the same agent). This prevents token collisions if two requests both
redact different IPs as `[TG:IP:1]`.

```go
type RequestScope struct {
    requestID string
    mappings  map[string]string
}

// When request completes, scope is destroyed
// Mappings never persist beyond the request lifecycle
```

### Failure Mode: Unresolved Token

If the cloud model returns a token that Tidegate can't reverse-map (corrupted,
hallucinated, or from a different request), Tidegate:
1. Logs it in the audit log as `unresolved_token`
2. Leaves the token as-is in the response (the agent sees `[TG:IP:1]`)
3. The agent can ask "what is [TG:IP:1]?" and Tidegate will NOT resolve it — the
   mapping is gone

This is intentional — it's better for the agent to see an opaque token than for
Tidegate to guess wrong and inject incorrect data.

---

## Issue 4: Ollama Summary Redaction Before Cloud Forwarding

### Problem

When Ollama produces a de-identified summary of local-only content, the summary
itself might still contain PII. A 7B model can miss things — it might summarize
"User admin@company.com logged in from 203.0.113.42" as "User admin@company.com
logged in from [REDACTED]" — it got the IP but leaked the email.

### Decision: Two-Stage Redaction Pipeline

Ollama's summary goes through the **same pattern-based redactor** before being
forwarded to the cloud. The pipeline is:

```
Local-only content (raw)
  │
  ▼
[1] Ollama summarization
  │   Prompt: "Summarize for an AI coding agent. Remove ALL PII:
  │   IPs, emails, phone numbers, credentials, hostnames, usernames.
  │   Keep: error messages, config keys, service names, query patterns,
  │   file structures, code logic."
  │
  ▼
[2] Pattern redaction (same regex patterns as the main redactor)
  │   Scan Ollama's output for any remaining PII patterns
  │   Replace with [TG:*] tokens
  │
  ▼
[3] Forward to cloud model
    Scrubbed summary that passed through both stages
```

### Why Two Stages?

- **Stage 1 (Ollama)** handles unstructured PII that regex can't catch — names,
  addresses, contextual references ("the user from Berlin", "the admin account")
- **Stage 2 (regex)** catches structured PII that Ollama missed — emails, IPs,
  API keys that survived summarization

Either stage alone is insufficient. Together they cover both structured and
unstructured PII leakage.

### Ollama Prompt Engineering

The summarization prompt is critical and will be iterated on. Initial version:

```
You are a privacy filter. Summarize the following content for an AI coding
agent. Remove ALL personally identifiable information:
- IP addresses (replace with [REDACTED_IP])
- Email addresses (replace with [REDACTED_EMAIL])
- Phone numbers (replace with [REDACTED_PHONE])
- API keys, tokens, passwords (replace with [REDACTED_SECRET])
- Usernames and real names (replace with [REDACTED_USER])
- Hostnames (replace with [REDACTED_HOST])

KEEP all technical information that is not PII:
- Error messages and stack traces
- Config keys and structure (but not values)
- Service names and package versions
- Code logic and patterns
- File paths (if they don't reveal user identity)

Output only the summary, no preamble.
```

---

## Issue 5: Bypass Vectors (Encoding, Fragmentation, Obfuscation)

### Problem

An agent (or a malicious prompt injection) could bypass redaction by:
- **Encoding**: base64-encoding an IP (`MjAzLjAuMTEzLjQy` decodes to `203.0.113.42`)
- **Fragmentation**: splitting a secret across multiple fields or messages
- **Obfuscation**: hex (`0x6b 0x0 0x0a`), unicode lookalikes, zero-width characters
- **Indirect reference**: "the IP I mentioned earlier" without repeating it
- **File path construction**: `cat /etc/nginx/` + `sites-enabled/myapp.conf`

### Decision: Layered Defense + Bounded Scope

Tidegate is **defense in depth, not a complete solution**. We acknowledge bypass
is possible and focus on making the common case safe, not the adversarial case
impossible.

### Layer 1: Pattern Redaction (catches the 95% case)

All regex patterns run on all content. This catches plaintext secrets regardless
of how they're framed. This alone handles the vast majority of real-world cases —
agents don't typically base64-encode IPs.

### Layer 2: Encoding Detection (v0.2)

Scan for common encodings and decode before pattern matching:

```go
type EncodingDetector struct {
    detectors []EncodingDetector
}

// Detect and decode before redaction
// - base64 (standard + URL-safe)
// - hex
// - URL encoding (%2e%2e%2f)
// - HTML entities (&#x2e;)

// If decoded content matches a sensitive pattern, redact the ENCODED form
// (don't send decoded content to cloud — just flag the encoded form as redacted)
```

If `MjAzLjAuMTEzLjQy` decodes to an IP, Tidegate replaces the entire base64
string with `[TG:IP:1]` — the cloud never sees either the encoded or decoded form.

### Layer 3: Contextual Redaction (v0.3)

Use the local Ollama model to pre-screen content for **implied sensitive data**:
- "the password from earlier" → if earlier content had a redacted password, flag this
- "connect to the database at the usual address" → if a DB address was redacted, flag this

This is expensive (local model call) and only runs on content that the classifier
flags as "suspicious" — references to previously-redacted data without repeating it.

### Layer 4: Rate Limiting + Anomaly Detection (v0.4)

- Track redaction density per request (e.g. 847 redactions in one request is unusual)
- Flag requests with high encoding density (lots of base64/hex is suspicious)
- Alert on patterns that look like deliberate exfiltration attempts

### What We Don't Try to Catch

- Zero-width character steganography — too expensive to scan for on every request
- Unicode lookalike attacks (`admіn@company.com` with Cyrillic і) — out of scope for v1
- Semantic references ("the thing I told you about") — Layer 3 catches some, not all
- Timing-based covert channels — not a text redaction problem

### Audit Log: Bypass Indicators

The audit log includes a `bypass_risk` field:

```sql
ALTER TABLE audit_entries ADD COLUMN bypass_risk TEXT;
-- Values: "none", "encoding_detected", "high_redaction_density",
--         "fragmented_sensitive_data", "manual_review_recommended"
```

When bypass risk is non-"none", the audit entry is flagged for manual review.

---

## Issue 6: Non-Path Entries in Path Rules (Command Output)

### Problem

The server preset has entries like `journalctl -u *` and `docker logs *` which are
commands, not file paths. The path-based rule engine can't match these.

### Decision: Separate Command-Output Rule Section

Introduce a `[cmd]` section in the rules config that matches command patterns
instead of file paths. When an agent executes a command (via tool use), Tidegate
matches the command against `[cmd]` rules and classifies the output.

```ini
# Rules for command output classification (not file paths)
[cmd]
# journalctl output contains IPs, usernames
journalctl -u *           = redact
journalctl --since *      = redact

# Docker logs may contain user data
docker logs *              = redact

# Process listings may contain secrets in args
ps aux                    = redact
ps -ef                    = redact
ss -tlnp                  = redact
netstat -tlnp             = redact

# Database queries — never to cloud
mysql *                   = local-only
psql *                    = local-only
sqlite3 *                 = local-only
redis-cli *               = local-only

# Block entirely — no reason for agents to read these
cat /etc/shadow           = block
cat ~/.ssh/id_*           = block
```

### How It Works

Agents communicate with LLMs via tool-use. When an agent runs `journalctl -u nginx`,
the tool result contains the command and its output. Tidegate:

1. Detects a tool-use result containing a shell command
2. Matches the command against `[cmd]` rules
3. Classifies the command's **output** according to the rule tier
4. Applies redaction/routing as normal to the output

### Implementation

```go
type CmdRule struct {
    Pattern string  // glob pattern: "journalctl -u *"
    Tier    Tier    // redact, local-only, block
}

type Classifier struct {
    pathRules  []PathRule
    cmdRules   []CmdRule
    patterns   []*Pattern
}

func (c *Classifier) ClassifyContent(block ContentBlock) Tier {
    // 1. If block is a tool result with a command, match cmd rules
    if block.IsToolResult && block.Command != "" {
        for _, rule := range c.cmdRules {
            if matchGlob(rule.Pattern, block.Command) {
                return rule.Tier
            }
        }
    }
    // 2. If block contains file content, match path rules
    if block.FilePath != "" {
        for _, rule := range c.pathRules {
            if matchGlob(rule.Pattern, block.FilePath) {
                return rule.Tier
            }
        }
    }
    // 3. Fall through to pattern-based classification
    return c.classifyByPatterns(block.Content)
}
```

### Updated server.conf

The `server.conf` preset is updated to use `[cmd]` for command-output rules
instead of mixing them into `[redact]` / `[local-only]` path sections.

---

## Issue 7: Per-Agent Identification

### Problem

Tidegate needs to know which agent is making the request (for per-agent rules and
audit logging), but the `ANTHROPIC_BASE_URL` env var doesn't carry agent identity.

### Decision: Agent Identification via Header + Auto-Config

### Method 1: Custom Header (Primary)

When Tidegate auto-configures an agent (`tidegate install --agent claude-code`),
it sets a custom header via the agent's config or a wrapper script:

```
X-Tidegate-Agent: claude-code
```

For agents that support custom headers (Claude Code, OpenCode, Hermes):
```bash
# Claude Code — in ~/.claude/config.json
{
  "extra_headers": {
    "X-Tidegate-Agent": "claude-code"
  }
}

# Hermes — in config.yaml
providers:
  anthropic:
    headers:
      X-Tidegate-Agent: hermes
```

### Method 2: API Key Fingerprint (Fallback)

If an agent doesn't support custom headers, Tidegate identifies the agent by
its API key fingerprint. During `tidegate install`, Tidegate registers the
agent's API key (SHA-256 hash, not the key itself) with an agent name:

```sql
CREATE TABLE agent_keys (
    key_hash   TEXT PRIMARY KEY,   -- SHA-256 of API key
    agent_name TEXT NOT NULL,      -- "claude-code", "codex", etc
    registered_at INTEGER NOT NULL
);
```

When a request arrives without the `X-Tidegate-Agent` header, Tidegate hashes
the API key in the request and looks up the agent name.

### Method 3: Port-Based Identification (Last Resort)

For agents that support neither custom headers nor expose their API key:
Tidegate can listen on multiple ports, one per agent:

```
localhost:8842  — default (unknown agent, most restrictive rules)
localhost:8843  — claude-code
localhost:8844  — codex
localhost:8845  — hermes
```

Each port maps to a known agent with specific rules. Configured via:
```bash
tidegate install --agent claude-code --port 8843
```

### Audit Log

All three methods populate the `agent` field in the audit log:
```sql
-- Agent identified via header
INSERT INTO audit_entries (agent, ...) VALUES ('claude-code', ...);

-- Agent identified via key fingerprint
INSERT INTO audit_entries (agent, ...) VALUES ('codex', ...);

-- Agent unknown (port 8842, no header, no registered key)
INSERT INTO audit_entries (agent, ...) VALUES ('unknown', ...);
```

---

## Issue 8: TLS Model

### Problem

The architecture says "HTTPS proxy" but agents send requests to
`http://localhost:8842` (plain HTTP). The relationship between the local proxy
connection and the upstream cloud connection needs to be explicit.

### Decision: Plain HTTP Locally, TLS Upstream

Tidegate uses a **split TLS model**:

```
Agent ──── HTTP (plaintext) ──→ Tidegate ──── HTTPS (TLS) ──→ Cloud API
         localhost:8842                    api.anthropic.com
         (no TLS needed)                    (TLS terminated by cloud)
```

### Why Plain HTTP Locally?

- The connection is `localhost` only — never leaves the machine
- TLS on localhost adds complexity (cert generation, trust stores) with no security benefit
- Agents that set `ANTHROPIC_BASE_URL=http://localhost:8842` expect plain HTTP
- Performance: no TLS handshake overhead for local connections

### Why TLS Upstream?

- The connection from Tidegate to the cloud API must use TLS (the cloud provider requires it)
- Tidegate terminates the local HTTP connection, then opens a new HTTPS connection to the cloud
- The cloud provider's TLS certificate is verified normally — Tidegate doesn't intercept it

### Implementation

```go
// Local listener: plain HTTP, localhost only
server := &http.Server{
    Addr: "127.0.0.1:8842",  // localhost only, no remote access
    Handler: proxyHandler,
}

// Upstream transport: standard HTTPS with TLS verification
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        // No custom certs — verify the cloud provider's cert normally
    },
}
```

### Optional: Local TLS (Paranoid Mode)

For environments where even localhost traffic must be encrypted (shared
multi-user servers, containers with host networking):

```ini
[gateway]
tls = true
tls_cert = ~/.config/tidegate/cert.pem
tls_key  = ~/.config/tidegate/key.pem
```

Tidegate generates a self-signed cert during `tidegate setup --tls` and
installs it in the system trust store. Agents connect via
`https://localhost:8842`. This is opt-in and not the default.

### Proxy vs HTTPS_PROXY

Two modes:

1. **Base URL override** (default): agents connect to `http://localhost:8842/anthropic`
   directly. Tidegate routes based on path prefix.

2. **HTTPS_PROXY mode** (fallback): agents connect to `api.anthropic.com` but the
   `HTTPS_PROXY` env var redirects through Tidegate. Tidegate uses CONNECT
   tunneling and intercepts the TLS stream. This is more complex and only used
   for agents that don't support base URL override.

Mode 1 is the default. Mode 2 is documented but not recommended — it requires
Tidegate to generate a CA certificate and install it in the agent's trust store,
which is fragile and platform-specific.

---

## Issue 9: Install Script GitHub Repo Placeholder

### Problem

The install script references `https://github.com/qo-roj/tidegate/releases/...`
which didn't exist initially.

### Decision: Two-Phase Release Strategy

### Phase 1: Local/Fleet Installation (Now)

The install script works without GitHub — it installs from a local binary or a
fleet-hosted mirror:

```bash
# Install from local binary (development)
./scripts/install.sh --local /path/to/tidegate-binary

# Install from fleet mirror (private)
curl -fsSL https://git.zitronenkuchen.tail5156c1.ts.net/tidegate/install.sh | bash

# Install from GitHub (public)
curl -fsSL https://raw.githubusercontent.com/qo-roj/tidegate/main/scripts/install.sh | bash
```

### Phase 2: GitHub Release (When Ready)

Once the Go code is written and the repo is public:
1. Create `github.com/qo-roj/tidegate` (done)
2. Set up GitHub Actions for cross-compilation (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64)
3. Tag releases, upload binaries as release assets
4. Point install.sh at GitHub releases

### Updated install.sh

The install script now:
1. Tries local binary first (`--local` flag or `TIDEGATE_BINARY` env var)
2. Tries GitHub releases (once the repo exists)
3. Falls back to building from source if Go is installed
4. Prints a clear error if none work

```bash
# In install.sh
DOWNLOAD_BASE="${TIDEGATE_MIRROR:-https://github.com/qo-roj/tidegate/releases}"

if [[ -n "${TIDEGATE_BINARY:-}" ]]; then
    # Local binary
    cp "$TIDEGATE_BINARY" "${INSTALL_DIR}/tidegate"
elif curl -fsSL "${DOWNLOAD_BASE}/download/${VERSION}/tidegate-${PLATFORM}-${ARCH}" -o ...; then
    # GitHub release
    :
elif command -v go &>/dev/null; then
    # Build from source
    git clone https://github.com/qo-roj/tidegate /tmp/tidegate-src
    cd /tmp/tidegate-src && go build -o "${INSTALL_DIR}/tidegate" ./cmd/tidegate
else
    echo "No binary available and Go not installed. Install Go or download manually."
    exit 1
fi
```

### GitHub Repo Name

The repo is at `github.com/qo-roj/tidegate`. The install script uses an env var so the
URL can be changed without code changes:

```bash
TIDEGATE_MIRROR=https://git.zitronenkuchen.tail5156c1.ts.net/tidegate \
  bash install.sh
```
---

## Issue 10: Session Continuity (v0.7.0)

### Problem

The per-request redactor allocated tokens from a counter that restarted at 1
on every request. Agents resend their own history — with originals — so the
same token value could refer to two different secrets across turns. A token
echoed from history then reverse-mapped to the wrong value:

```
turn 1: [TG:IP:1] = 203.0.113.42
turn 2: [TG:IP:1] = 198.51.100.7  (history echo expanded to the new value)
```

This was demonstrated by a failing probe before the fix (regression test:
`TestCrossTurnTokenCollision`).

### Decision: Session-Scoped Vault

A SQLite vault owns token numbering per conversation:

- `tokens(session, token, category, original, expires, ...)` — stable,
  per-session, expiring mappings
- `counters(session, category, seq)` — monotonic allocation inside a
  transaction, so concurrent requests cannot collide
- Session identity: `X-Tidegate-Session` header → token ownership → opening
  fingerprint → none
- Reverse mapping is limited to tokens present in the incoming request
  (defence against using the gateway as a value oracle)

### Why Not Delta-Only Forwarding?

The obvious optimisation — forward prior turns byte-for-byte and only process
the newest message, as a context compressor would — is unsafe here. The agent
stores and resends **originals**, so unprocessed history would reach the cloud
unredacted. Every message is therefore still classified and redacted.

Instead the cost is reduced with a **content-addressed redaction cache**:
`sha256(block) + session + rule-set fingerprint → redacted form`. A hit is
equivalent to recomputation by construction. This keeps history byte-identical
across turns, which is also what provider prompt caches want.

### Trade-offs

- The vault holds plaintext originals at rest (`0600`, 24h TTL). Necessary for
  multi-turn continuity; documented in the threat model.
- A client that forks one conversation into parallel branches will reuse the
  same session tokens. Values still resolve correctly; only numbering is shared.
- Stateless calls (`tidegate text`, requests without messages) keep the old
  per-request behaviour.

---

## Issue 11: Content-Shape Awareness (v0.7.0)

### Problem

Pure regex redaction is blind to structure. Two live defects came from this:

- a phone pattern parsed `15:07:51.712345 2026` as NANP `712-345-2026`
  (fixed narrowly in v0.6.3 by re-anchoring the regex)
- hostnames leaked in positions the patterns did not model (DocumentRoot
  paths, URL hosts — v0.6.2/0.6.3)

Narrow regex fixes address instances; they do not address the class.

### Decision: Detect Shape, Then Transform

`internal/content.Detect` classifies a block as json / log / code / diff /
text. Two transforms use the result:

1. **JSON key redaction** — values under `password`, `api_key`,
   `authorization`, `dsn`, cookie/session keys are replaced wholesale. This
   catches base64 blobs, names, and connection strings no pattern recognises,
   and the document is never re-encoded (raw `"key":"value"` rewrite + a
   `json.Valid` check that discards a broken rewrite).
2. **Timestamp shielding** — timestamp spans are swapped for inert sentinels
   before pattern matching and restored afterwards. Patterns cannot fire
   inside a timestamp, and the line keeps its exact bytes.

Both preserve byte layout, so prompt prefixes stay stable.

### Trade-off

Detection is heuristic. A malformed or mixed document falls back to `text` and
pattern-only redaction. JSON key redaction is deliberately conservative:
only string values directly under a sensitive key, never whole objects.
