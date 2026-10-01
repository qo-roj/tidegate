# Tidegate — Rules Guide

## How Rules Work

Tidegate uses a layered rule system to classify content before it reaches any LLM.

### Classification Tiers

Every piece of content in an agent request is assigned exactly one tier:

| Tier | Cloud sees it? | Ollama sees it? | Agent sees result? |
|---|---|---|---|
| **public** | ✅ as-is | — | ✅ |
| **redacted** | ✅ with patterns stripped | — | ✅ |
| **local-only** | ❌ never | ✅ raw data + produces scrubbed summary | ✅ sees summary |
| **blocked** | ❌ never | ❌ never | ❌ error returned to agent |

### Rule Resolution Order

Rules are evaluated in this order (later rules override earlier ones):

1. **Built-in defaults** (`rules/defaults.conf`)
2. **Preset rules** (e.g. `rules/presets/server.conf`)
3. **User config** (`~/.config/tidegate/tidegate.conf`)
4. **Project-local config** (`.tidegate.conf` in project root)
5. **CLI flags** (highest priority, temporary)

When two rules match the same path, the more specific one wins. Within the same
specificity, the later rule wins.

## Rule Syntax

### Path Rules

Paths use glob patterns (doublestar — `**` matches recursively).

```ini
[block]
~/.ssh/id_*
/etc/shadow
**/.env

[local-only]
~/.config/himalaya/*
/var/log/**
**/credentials*

[redact]
~/.zsh_history
/var/log/nginx/access.log
```

### Command-Output Rules

Command rules classify the **output** of commands that agents run (via tool use).
These are separate from path rules because they match command strings, not file paths.

```ini
[cmd]
# Redact command output (strip IPs, emails, etc.)
journalctl -u *           = redact
docker logs *              = redact
ps aux                    = redact
ss -tlnp                  = redact

# Route command output to local Ollama only (never to cloud)
mysql *                   = local-only
psql *                    = local-only
redis-cli *               = local-only

# Block — agent should never run this
cat /etc/shadow           = block
```

How it works: when an agent runs a command (e.g. `journalctl -u nginx`), the
tool result contains the command and its output. Tidegate matches the command
against `[cmd]` rules and classifies the output accordingly. Path rules do NOT
apply to command output — they only apply to file content.

**Special prefixes:**
- `~/` — expands to current user's home directory
- `~USER/` — expands to a specific user's home
- `/` — absolute path from filesystem root
- `**/` — matches any number of directories
- `*` — matches anything within a single path segment

### Pattern Rules

Redaction patterns are regex-based. Each pattern has:
- A name (for config and audit log)
- A regex that matches sensitive data
- A replacement token in the form `[TG:CATEGORY:N]` (e.g. `[TG:IP:1]`, `[TG:EMAIL:2]`) — one token per distinct value, restored in responses

Built-in patterns:

| Name | Matches | Example | Replaced With |
|---|---|---|---|
| `ipv4` | Public IPv4 addresses (RFC1918 ranges go to `ipv4_private` when enabled) | `203.0.113.42` | `[TG:IP:1]` |
| `ipv4_private` | Private IPv4 ranges (opt-in: server/paranoid presets) | `10.1.2.3` | `[TG:IP:1]` |
| `ipv6` | Full-form IPv6 addresses | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` | `[TG:IP:1]` |
| `email` | Email addresses | `user@example.com` | `[TG:EMAIL:1]` |
| `phone` | Phone numbers (international and NANP) | `+49 170 1234567`, `555-123-4567` | `[TG:PHONE:1]` |
| `api_key_github` | GitHub tokens (`ghp_…`, `gho_…`, `ghs_…`, `ghu_…`, `ghr_…`, `github_pat_…`) | `ghp_xxxx...` | `[TG:TOKEN:1]` |
| `api_key_openai` | OpenAI keys | `sk-proj-xxxx...` | `[TG:TOKEN:1]` |
| `api_key_anthropic` | Anthropic keys | `sk-ant-xxxx...` | `[TG:TOKEN:1]` |
| `api_key_aws` | AWS access keys | `AKIAxxxx...` | `[TG:TOKEN:1]` |
| `api_key_aws_secret` | AWS secret keys (`aws_secret_access_key = …`) | `aws_secret_access_key = xxxx...` | `[TG:TOKEN:1]` |
| `api_key_google` | Google API keys | `AIza...` | `[TG:TOKEN:1]` |
| `api_key_stripe` | Stripe keys | `sk_live_xxxx...` | `[TG:TOKEN:1]` |
| `api_key_slack` | Slack tokens | `xoxb-xxxx...` | `[TG:TOKEN:1]` |
| `api_key_gitlab` | GitLab tokens | `glpat-xxxx...` | `[TG:TOKEN:1]` |
| `bearer_token` | Bearer tokens | `Bearer xxxx...` | `[TG:TOKEN:1]` |
| `jwt` | JWT tokens | `eyJxxxx...` | `[TG:JWT:1]` |
| `private_key` | PEM private keys (RSA/EC/DSA/OPENSSH/PGP blocks) | `-----BEGIN ... PRIVATE KEY-----` | `[TG:KEY:1]` |
| `mac_address` | MAC addresses | `00:1B:44:11:3A:B7` | `[TG:MAC:1]` |
| `database_connection` | Database URLs (postgres/mysql/mongodb/redis://) | `postgres://user:***@host/db` | `[TG:DBURL:1]` |
| `credit_card` | 13–16 digit card numbers (with separators) | `4111 1111 1111 1111` | `[TG:CC:1]` |
| `ssn_us` | US SSNs | `123-45-6789` | `[TG:SSN:1]` |
| `hostname_internal` | Internal hostnames (opt-in: server/paranoid presets) | `machine.internal` | `[TG:HOST:1]` |
| `iban` | IBANs (opt-in: paranoid, training-data presets) | `NL91ABNA0417162300` | `[TG:IBAN:1]` |
| `passport` | Passport numbers (opt-in: paranoid, training-data presets) | `K12345678` | `[TG:PASSPORT:1]` |
| `high_entropy_secret` | 36+ char alphanumeric strings (opt-in: training-data preset; matches UUIDs too — deliberate fail-safe) | `zZ9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2H1` | `[TG:SECRET:1]` |
| `syslog_hostname` | Hostnames in syslog-style timestamped lines with process tag (structure-anchored: timestamp and process stay, hostname tokenized) | `Sep  3 17:54:01 web01 sshd[1]: …` | `Sep  3 17:54:01 [TG:HOST:1] sshd[1]: …` |
| `passwd_username` | Account names in passwd/shadow-style lines (structure-anchored: field layout stays, name tokenized) | `alice:x:1000:1000:…` | `[TG:USER:1]:x:1000:1000:…` |
| `accesslog_hostname` | Virtual host in Apache/nginx combined access logs (structure-anchored: `vhost[:port] client - - [timestamp]`; port, client and timestamp stay, vhost tokenized). Default-on since v0.6.2 — found live: vhost leaked while client IP was redacted | `myhost.com:443 1.2.3.4 - - [01/Oct/2026:14:44:22 +0200] …` | `[TG:HOST:1]:443 1.2.3.4 - - [01/Oct/2026:14:44:22 +0200] …` |

Pattern toggles live in `[redaction.patterns]` (e.g. `syslog_hostname = false`); defaults are set in `rules/defaults.conf`. Extended patterns (private IPs, internal hostnames, IBAN, passport, high-entropy secrets) are opt-in per preset.

### Custom Patterns

```ini
[redaction.custom]
# Custom patterns use named regex groups
internal_host = '(?P<value>[a-z0-9-]+\.internal\.company\.com)'
internal_host_replacement = '[INTERNAL_HOST_REDACTED_N]'

# Or via CLI
# tidegate config add-pattern internal_host '[a-z0-9-]+\.internal\.company\.com' '[INTERNAL_HOST_REDACTED_N]'
```

## Presets

Presets are named collections of rules for common scenarios:

```bash
# List available presets
tidegate presets
# desktop    — Omarchy / personal workstation
# server     — Production server with user data
# paranoid   — Maximum redaction, minimal cloud exposure

# Use a preset
tidegate config set preset server

# Combine presets (later ones extend earlier ones)
tidegate config set preset desktop,server
```

## Common Patterns

### "My agent needs to read this file but it has secrets in it"

```ini
[redact]
/path/to/file.conf
```

The file goes to the cloud with secrets stripped. The agent can see the structure
but not the actual credentials.

### "My agent should never touch this file at all"

```ini
[block]
/path/to/sensitive/file
```

The agent receives an error. It can't read this file through any model.

### "This file has user data — I want Ollama to summarize it"

```ini
[local-only]
/path/to/user-data.json
```

Ollama reads the raw file, produces a de-identified summary ("JSON file with 847
users, fields: id, email, phone, created_at"), and the summary goes to the cloud.

### "This whole directory is sensitive"

```ini
[local-only]
/var/lib/myapp/data/**
```

Everything under `/var/lib/myapp/data/` is routed to Ollama only.

### "I want to whitelist a specific file from a blocked directory"

```ini
[block]
~/.ssh/**

[redact]
~/.ssh/config
```

The SSH config is redacted (hostnames, IPs stripped) but readable. Private keys
remain blocked.

### "Per-agent rules — different agents get different access"

```ini
[agent:claude]
[redact]
~/projects/**

[agent:codex]
[block]
~/projects/company-internal/**
```

Claude can read your projects (redacted). Codex can't access internal company
projects at all.

## Testing Your Rules

```bash
# Test how a file would be classified
tidegate classify ~/.ssh/id_ed25519
# → tier: blocked
# → reason: matches block rule ~/.ssh/id_*

tidegate classify /etc/nginx/nginx.conf
# → tier: redacted
# → reason: matches redact rule /etc/nginx/**
# → redactions: 2 IPs found, 0 emails, 1 token

tidegate classify /var/log/nginx/access.log
# → tier: redacted
# → redactions: 847 IPs, 23 emails, 0 tokens

# Test what the cloud model would actually receive
tidegate dry-run --file /etc/nginx/nginx.conf
# Shows the redacted output that would be sent to the cloud
```