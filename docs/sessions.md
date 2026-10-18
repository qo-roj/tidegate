# Sessions & the Token Vault

Tidegate's redaction tokens (`[TG:IP:1]`) are only useful if they mean the same
thing for the whole conversation. Before v0.7.0 they didn't: every request
built a fresh redactor whose counters started at 1, and the mapping was
discarded when the request finished.

That produced a real correctness bug. Agents resend their own history on every
turn — including values Tidegate redacted last turn — so turn 2 could allocate
`[TG:IP:1]` to a *different* address than turn 1. When the model echoed the
historical token, the reverse mapper expanded it to the wrong value:

```
turn 1   host is [TG:IP:1]                              (203.0.113.42)
turn 2   history: [TG:IP:1] ; new host is [TG:IP:1]     (198.51.100.7)
restore  history: 198.51.100.7 ; new: 198.51.100.7     ← wrong
```

## What the vault does

`internal/vault` is a SQLite store (default `~/.local/share/tidegate/vault.db`,
mode `0600`) that owns token numbering per conversation:

- **Stable** — the same value in the same session always gets the same token.
- **Isolated** — sessions number independently; `[TG:IP:1]` in two
  conversations can refer to different values without collision.
- **Persistent** — mappings survive gateway restarts, so a long-running agent
  session keeps working.
- **Expiring** — entries are deleted after `vault_ttl_hours` (default 24).
  Originals are never logged.

Token allocation is `INSERT`-serialised per session and category, so concurrent
requests cannot hand out the same number twice.

## How a session is identified

1. **`X-Tidegate-Session` header** — explicit, hashed before storage. Use this
   when the client can set headers (gateway mode, custom wrappers).
2. **Token ownership** — if the request carries tokens that belong to exactly
   one known session, that session is adopted. Conversations identify
   themselves; no header needed.
3. **Opening fingerprint** — otherwise the first system message plus the first
   user message (and the agent name) are hashed. Both stay byte-identical as
   the conversation grows, so the id is stable.
4. **Stateless** — requests with no messages get no session and fall back to
   the old per-request behaviour.

The header is stripped before forwarding and never reaches a provider.

## Reverse mapping is scoped

Restoring is restricted to tokens that appeared in the incoming request (or
were allocated for it). A model that hallucinates a token — or quotes one from
another conversation — gets the token back unchanged. The gateway cannot be
used as an oracle for values it never sent.

## Content-addressed redaction cache

Because history is re-sent as originals, it must be re-redacted on every turn.
To avoid re-scanning identical blocks, `redactContent` hashes each block and
caches the redacted form per session and per rule-set fingerprint
(`redaction-v2` + enabled pattern names). A cache hit is always equivalent to
recomputing: same input, same session, same rules.

Cache entries share the vault TTL and are counted in
`tidegate_redaction_cache_hits_total`.

## Why Tidegate does not skip history ("delta-only" forwarding)

Headroom, the project that inspired this layer, forwards prior turns
byte-for-byte and only compresses the newest delta. That is safe for a
compressor: the bytes are unchanged. It is **not** safe for a redaction
gateway. The agent's history contains originals — tool outputs and restored
model text — so skipping it would forward secrets unredacted. Tidegate still
processes every message; what it saves is token churn and cache misses, not
redaction work. The redaction cache recovers most of the CPU cost.

## Configuration

```ini
[gateway]
# Hours a token stays resolvable (default 24, max 8760)
vault_ttl_hours = 24
```

CLI: `--vault-ttl-hours N`. Vault path is fixed at
`~/.local/share/tidegate/vault.db`.

## Operational notes

- Losing the vault is safe: the next request re-redacts and re-tokenises.
  In-flight conversations lose continuity, nothing leaks.
- The vault holds plaintext originals. It is `0600`, its directory is `0700`,
  and entries expire. Treat it like shell history: local-only, not backed up
  to third parties.
- `tidegate_vault_tokens` / `tidegate_vault_cache_entries` expose live counts.
