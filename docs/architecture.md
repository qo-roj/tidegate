# Tidegate — Architecture

## Overview

Tidegate is a local HTTPS proxy daemon that intercepts, classifies, redacts, and routes
LLM API calls between AI coding agents and cloud providers.

```
                                    ┌──────────────┐
                                    │  Agent CLI   │
                                    │ (Claude etc) │
                                    └──────┬───────┘
                                           │ HTTP(S) request
                                           │ (to localhost:8842)
                                           ▼
┌──────────────────────────────────────────────────────────────┐
│  Tidegate Gateway (localhost:8842)                          │
│                                                              │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐     │
│  │  Proxy      │───▶│  Classifier  │───▶│  Redactor   │     │
│  │  (intercept │    │  (classify   │    │  (replace   │     │
│  │   request)  │    │   content)   │    │   sensitive  │     │
│  └─────────────┘    └──────────────┘    │   patterns)  │     │
│                                          └──────┬───────┘     │
│                                                  │             │
│                                          ┌───────┴───────┐    │
│                                          ▼               ▼    │
│                                   ┌────────────┐  ┌────────┐  │
│                                   │  Router     │  │ Audit │  │
│                                   │  (cloud or  │  │ Log   │  │
│                                   │   local)    │  │       │  │
│                                   └─────┬──────┘  └────────┘  │
│                                         │                     │
└─────────────────────────────────────────┼─────────────────────┘
                                          │
                          ┌───────────────┴───────────────┐
                          ▼                               ▼
                   ┌──────────────┐              ┌──────────────┐
                   │  Cloud API   │              │  Local Ollama│
                   │  (scrubbed)  │              │  (full data)  │
                   │              │              │              │
                   │ api.anthropic│              │ localhost:   │
                   │ api.openai   │              │ 11434        │
                   └──────────────┘              └──────────────┘
```

## Component Details

### 1. Proxy Server (`internal/proxy/`)

- Go `net/http` reverse proxy with split TLS model (see [Design Decisions §8](design-decisions.md#issue-8-tls-model))
- Listens on `localhost:8842` — **plain HTTP** (localhost only, no TLS needed)
- Upstream connections to cloud APIs use **HTTPS** (TLS terminated by cloud provider)
- Routes based on path prefix:
  - `/anthropic/*` → Anthropic API
  - `/openai/*` → OpenAI API
  - `/xai/*` → xAI API
  - `/ollama/*` → local Ollama (passthrough, no redaction needed)
- Agent identification via `X-Tidegate-Agent` header, API key fingerprint, or port (see [Design Decisions §7](design-decisions.md#issue-7-per-agent-identification))
- Streaming: SSE responses pass through with real-time token reverse-mapping (see [Design Decisions §2](design-decisions.md#issue-2-streaming-sse-support))
- Transparent to agents — they just hit `localhost:8842` instead of the real API

### 2. Classifier (`internal/classify/`)

Scans request content and assigns a tier to each **content block** (not whole
request). See [Design Decisions §1](design-decisions.md#issue-1-mixed-tier-content-in-single-requests)
for the mixed-tier resolution.

```go
type Tier int

const (
    TierPublic   Tier = iota  // send to cloud as-is
    TierRedacted              // scrub patterns, then send
    TierLocalOnly             // route to Ollama only
    TierBlocked               // refuse access entirely
)
```

Classification sources:
- **Path rules** — from config file (`block`, `local-only`, `redact` sections)
- **Command rules** — `[cmd]` section matches command output (e.g. `journalctl -u *`)
- **Pattern matches** — regex patterns for IPs, emails, API keys, etc.
- **Content heuristics** — if a file path or command appears in the request, classify based on rules

When a single content block contains multiple sub-tier elements, the block is
escalated to the **highest** tier present (conservative — when in doubt, escalate).

### 3. Redactor (`internal/redact/`)

- Applies regex replacements based on enabled patterns
- Token format: `[TG:IP:1]`, `[TG:EMAIL:3]`, `[TG:TOKEN:1]` — distinctive `TG:` prefix prevents collisions
- Reverse-maps tokens in response content (including SSE streams) so the agent can act on real values
- Fuzzy matching handles reformatted tokens (quotes stripped, brackets removed)
- With a vault attached, mappings are **session-scoped and persistent**: the same value keeps the same token across turns, and each conversation numbers independently — see [Sessions](sessions.md)
- Without a vault (stateless calls), behaviour is per-request and in-memory
- Restore is scoped to tokens that appeared in the request or were allocated for it, so unrelated tokens stay opaque
- The vault (not the redactor) owns persistence; it lives at `~/.local/share/tidegate/vault.db`, mode `0600`, with a TTL

See [Design Decisions §3](design-decisions.md#issue-3-token-reverse-mapping-robustness) for
token format and fuzzy matching details.

```go
type Redactor struct {
    patterns []*Pattern
    store    TokenStore   // optional session vault
    session  string
    seen     map[string]bool // tokens this request may resolve
    mu       sync.Mutex
}

func (r *Redactor) Redact(content string) string
func (r *Redactor) Restore(content string) string
func (r *Redactor) NoteTokens(content string)       // history tokens become resolvable
func (r *Redactor) Snapshot() map[string]string     // scoped token view
```

### 4. Router (`internal/route/`)

Decision logic for where content goes:

```
Content tier = PUBLIC    → forward to original cloud API (as-is)
Content tier = REDACTED  → run redactor → forward to cloud API (scrubbed)
Content tier = LOCAL_ONLY→ send to Ollama → get summary → forward summary to cloud
Content tier = BLOCKED   → return error to agent: "access denied by Tidegate"
```

For `LOCAL_ONLY` with Ollama (two-stage redaction pipeline — see
[Design Decisions §4](design-decisions.md#issue-4-ollama-summary-redaction-before-cloud-forwarding)):

1. Send raw content to local Ollama with a summarization prompt (removes unstructured PII)
2. Ollama returns a de-identified summary
3. The summary passes through the **same pattern redactor** (removes structured PII that Ollama missed)
4. The double-scrubbed summary is sent to the cloud model as the agent's context

If no Ollama is configured, `LOCAL_ONLY` content is blocked entirely.

### 5. Audit Log (`internal/audit/`)

SQLite database at `~/.local/share/tidegate/audit.db`

Tables:
```sql
CREATE TABLE audit_entries (
    id          INTEGER PRIMARY KEY,
    timestamp   DATETIME NOT NULL,
    agent       TEXT NOT NULL,         -- "claude", "codex", etc
    provider    TEXT NOT NULL,         -- "anthropic", "openai", "ollama"
    action      TEXT NOT NULL,         -- "read", "write", "query", "exec"
    target      TEXT,                  -- file path, command, query
    tier        TEXT NOT NULL,         -- "public", "redacted", "local_only", "blocked"
    redactions  TEXT,                  -- JSON: {"ips": 3, "emails": 2, ...}
    approved    BOOLEAN DEFAULT 0,
    notes       TEXT
);
```

CLI query:
```bash
tidegate audit                    # last 24h summary
tidegate audit --live             # tail -f style
tidegate audit --agent claude     # filter by agent
tidegate audit --since 2h         # last 2 hours
tidegate audit --detail <id>      # full entry detail
tidegate audit --export > log.json # export for compliance
```

### 6. Ollama Integration (`internal/ollama/`)

- Connects to local Ollama at `http://localhost:11434` by default
- Uses a configured model (default: `llama3:8b`)
- Sends a summarization prompt for `local-only` content
- Returns the de-identified summary for cloud forwarding
- If Ollama is down, falls back to blocking `local-only` content

### 7. Token Vault (`internal/vault/`)

SQLite store for session-scoped tokens and the content-addressed redaction
cache. Allocates tokens deterministically per `(session, category, value)`,
sweeps expired entries every 10 minutes, and answers lineage queries
("which session owns these tokens?"). See [Sessions](sessions.md).

### 8. Content Shaper (`internal/content/`)

Detects block shape (`json`, `log`, `code`, `diff`, `text`) and applies
shape-specific transforms:

- JSON: values under sensitive keys (`password`, `api_key`, `authorization`,
  DSNs, cookies) are redacted wholesale — this catches secrets no regex
  recognises, and never re-encodes the document.
- Logs/prose/JSON: timestamp spans are replaced with inert sentinels before
  pattern redaction and restored afterwards, so patterns cannot fire inside a
  timestamp (the v0.6.3 phone false positive class).

### 9. Wrap (`internal/wrap/`)

Edits agent CLIs' own configuration to point at the gateway, records the prior
values, and restores them on `unwrap`. Supported: Claude Code, Codex, OpenCode,
plus a shell-export target. See [Wrap](wrap.md).

### 10. Metrics (`internal/metrics/`)

In-process counters exposed as Prometheus text and JSON on
`127.0.0.1:9116` (`--metrics-addr`, `--no-metrics`). See [Metrics](metrics.md).

## Request Flow (Detailed)

```
1. Agent sends request to localhost:8842/anthropic/v1/messages
   Body: {
     "model": "claude-opus-4-20250514",
     "messages": [
       {"role": "user", "content": "Here's my nginx config: <file content>..."}
     ]
   }

2. Proxy receives request, extracts message content

3. Classifier scans content:
   - "<file content>" matches path rule for /etc/nginx/ → tier: REDACTED
   - File contains: server_name myapp.com; → email pattern? No. IP? No.
   - File contains: ssl_certificate /etc/letsencrypt/live/myapp.com/... → path rule → local-only for letsencrypt
   - Result: mixed tiers within one request

4. Redactor processes REDACTED content:
   - Scans for patterns
   - Finds: 203.0.113.42 in a log line → replaces with [IP_REDACTED_1]
   - Finds: admin@myapp.com → replaces with [EMAIL_REDACTED_1]
   - Keeps mapping in memory

5. Router:
   - Public portions → forward as-is
   - Redacted portions → forward with replacements
   - Local-only portions → send to Ollama for summarization → forward summary
   - Blocked portions → remove from request, log as blocked

6. Cloud API receives scrubbed request, returns response

7. Redactor reverse-maps response:
   - If cloud says "check [IP_REDACTED_1]" → restore to "check 203.0.113.42"
   - Agent sees real values in the response

8. Audit log records:
   - agent=claude, action=read, target=/etc/nginx/nginx.conf
   - tier=redacted, redactions={"ips":1,"emails":1}
   - provider=anthropic, approved=true (auto-rule)

9. Agent receives response, continues working
```

## Configuration Resolution Order

1. Built-in defaults (`rules/defaults.conf`)
2. Preset rules (`rules/presets/desktop.conf` or `server.conf`)
3. User config (`~/.config/tidegate/tidegate.conf`)
4. Project-local config (`./.tidegate.conf` — overrides user config)
5. CLI flags (highest priority)

## Performance Considerations

- Redaction is regex-based — O(n) in content size per pattern
- Typical agent request: 10-100KB → sub-millisecond redaction
- Identical blocks in a session are served from the redaction cache (hash
  lookup + SQLite read) instead of being re-scanned
- Token allocation is one prepared statement per new value; lookups hit the
  in-process map first
- Ollama summarization adds latency for local-only content (1-5s)
- Audit log is async (buffered write queue), non-blocking
- Proxy adds <1ms overhead for pass-through (public content)

## Security Considerations

- The mapping table (redaction token → original) lives in the session vault at
  `~/.local/share/tidegate/vault.db` (mode `0600`, directory `0700`)
- Mappings are **scoped per session**; each conversation numbers independently,
  so one session's token cannot resolve another session's value
- Mappings expire (default 24h) and are never logged or sent upstream
- Reverse mapping only resolves tokens the current request actually carried;
  invented or foreign tokens stay opaque
- The vault holds plaintext originals at rest — treat it like shell history;
  it is excluded from third-party backups by default
- Process runs as user (not root), reads only files the user can read
- The proxy itself is localhost-only — no remote access to the gateway
- Bypass vectors (encoding, fragmentation, obfuscation) are addressed via layered
  defense — see [Design Decisions §5](design-decisions.md#issue-5-bypass-vectors-encoding-fragmentation-obfuscation).
  Tidegate is defense in depth, not a complete solution. The audit log includes
  `bypass_risk` indicators for manual review.