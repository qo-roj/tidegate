# Tidegate — Threat Model

## The Problem Space

AI coding agents (Claude Code, Codex, OpenCode, Hermes, Grok CLI) operate by reading
files, executing commands, and sending the results as context to cloud LLM APIs.
This means the contents of your filesystem — configs, logs, credentials, source code,
personal data — are transmitted to third-party cloud providers on every agent request.

No agent harness currently provides a data protection layer between your machine
and the cloud provider.

## What We Protect Against

### 1. Passive Data Exfiltration via Agent Context

**Scenario:** An agent reads `~/.git-credentials` to understand your git setup.
The file contents (containing GitHub tokens) are included in the API request body
sent to `api.anthropic.com`.

**Mitigation:** Path-based rules classify `~/.git-credentials` as `blocked`.
Tidegate removes the content from the request before forwarding. The agent receives
an error: "access denied by Tidegate."

### 2. Log Leakage

**Scenario:** An agent runs `journalctl -u nginx --since "1 hour ago"` to diagnose
a crash. The log contains user IP addresses, email addresses in user agents, and
API tokens in query parameters. All of this goes to the cloud provider.

**Mitigation:** Pattern-based redaction strips IPs, emails, and token patterns
from the log output before forwarding. The cloud model sees: "request from
[IP_REDACTED_1] with user agent containing [EMAIL_REDACTED_1]". The agent can still
reason about the structure and patterns without seeing the actual values.

### 3. Credential Exposure in Config Files

**Scenario:** An agent reads `/etc/nginx/nginx.conf` to debug a config issue.
The file contains `proxy_pass http://internal-service:8080;` revealing internal
network topology, and `ssl_certificate_key /etc/letsencrypt/live/myapp.com/privkey.pem;`
revealing cert paths.

**Mitigation:** Path rules classify `/etc/letsencrypt/` as `local-only`. The
letsencrypt references are routed to Ollama, which produces a summary: "SSL
certificate configured for myapp.com via Let's Encrypt." Internal hostnames are
redacted by pattern.

### 4. Shell History Leakage

**Scenario:** An agent reads `~/.zsh_history` to understand recent work context.
The history contains pasted passwords, `curl` commands with API keys in the URL,
and `ssh user@internal-host` commands revealing internal hostnames.

**Mitigation:** Path rules classify `~/.zsh_history` as `redact`. All IPs, API
key patterns, and sensitive patterns are stripped. The agent sees the command
structure without the sensitive arguments.

### 5. Database Content Exposure

**Scenario:** An agent runs `SELECT * FROM users LIMIT 5` to understand schema.
The result set contains email addresses, phone numbers, and hashed passwords.
This goes to the cloud provider.

**Mitigation:** SQL query results are classified as `local-only` by default.
Ollama reads the raw result, produces a de-identified summary: "users table has
columns: id, email, phone, password_hash. 5 rows returned. Emails are in standard
format, passwords are bcrypt hashes." The summary goes to the cloud, not the raw
data.

## What We Do NOT Protect Against

### 1. Malicious Cloud Provider

If the cloud provider (OpenAI, Anthropic) logs and reconstructs data from
redacted context, Tidegate cannot prevent that. We reduce the surface area, but
we cannot control what the provider does with what we send them.

**Mitigation:** Use `local-only` classification for anything truly critical.
With Ollama, that data never leaves your machine.

### 2. Side-Channel Exfiltration

An agent could write sensitive data to a file that gets synced to cloud storage
(Dropbox, iCloud, Google Drive), or exfiltrate via a DNS query, or embed it in a
git commit that gets pushed to a remote. Encoding-based bypass (base64, hex)
is addressed in [Design Decisions §5](design-decisions.md#issue-5-bypass-vectors-encoding-fragmentation-obfuscation).

**Mitigation:** Tidegate only intercepts LLM API calls. It cannot monitor all
possible exfiltration channels. Layered defense (pattern redaction → encoding
detection → contextual redaction → anomaly detection) catches common bypasses.
The audit log flags `bypass_risk` for manual review. Future versions could
integrate with eBPF for broader monitoring.

### 3. Compromised Local Model

If the local Ollama model is compromised (e.g., a malicious model file), it could
exfiltrate data through its own channels.

**Mitigation:** Use official model sources. Verify model checksums. Tidegate
could add model integrity checks in future versions.

### 4. Social Engineering of the Mapping Table

An attacker could craft a prompt that tricks the agent into revealing the
redaction mappings (e.g., "What is the real value of [IP_REDACTED_1]?").

**Mitigation:** The mapping table is never exposed to the agent. When the agent
responds, Tidegate reverse-maps tokens, but the agent never sees the mapping
table itself. The cloud model only sees the redacted token, never the original
value.

### 5. Zero-Day in Agent Harness

A vulnerability in Claude Code, Codex, etc. could allow bypassing the proxy
entirely (e.g., hardcoded API endpoint that ignores env vars).

**Mitigation:** Tidegate can optionally use `iptables`/`nftables` rules to
redirect all outbound traffic to known LLM API endpoints through the proxy,
making bypass harder. This is a future feature.

## Trust Model

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Agent      │     │  Tidegate   │     │  Cloud API   │
│  UNTRUSTED  │────▶│  TRUSTED     │────▶│  SEMI-TRUSTED│
│             │     │  (local,     │     │  (we send    │
│  (reads     │     │   user       │     │   scrubbed   │
│   your      │     │   controlled)│     │   data only) │
│   files)    │     │              │     │              │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Local Ollama │
                    │  TRUSTED      │
                    │  (local,      │
                    │   offline)    │
                    └──────────────┘
```

- **Agent**: Untrusted. It reads your files and wants to send everything to the
  cloud. Tidegate intercepts and sanitizes.
- **Tidegate**: Trusted. Runs locally, user-configured, open source, auditable.
  The only component that sees both redacted and original data. Its session
  vault (`vault.db`) holds plaintext originals at rest for token continuity —
  mode `0600`, directory `0700`, 24h TTL, local only.
- **Cloud API**: Semi-trusted. We send it scrubbed data. We trust it to process
  our request but we minimize what we reveal.
- **Local Ollama**: Trusted. Runs locally, offline. Sees raw sensitive data but
  never sends it anywhere.

## Data at Rest

The session vault is the one place Tidegate writes originals to disk. It exists
so a token can still mean the same thing five turns later.

- `~/.local/share/tidegate/vault.db`, mode `0600`, parent directory `0700`
- Entries expire after `vault_ttl_hours` (default 24) and are swept every
  10 minutes; expired tokens no longer resolve
- Deleting the file is safe: the next request re-redacts and re-tokenises
- Anyone who can read the file can read the redacted values. It is not
  encrypted at rest — use full-disk encryption if that matters to you
- Do not include it in third-party backups

## Scope

Tidegate is **defense in depth**, not a complete security solution. It
dramatically reduces the data surface area exposed to cloud providers, but
cannot guarantee zero data leakage. The audit log provides verifiable evidence
of what was sent where.

The goal is to make the default state of an AI agent on your machine **safe**
rather than **unsafe** — the way disk encryption is the default, not an opt-in.