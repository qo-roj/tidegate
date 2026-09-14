# Tidegate

A local redaction gateway for AI coding agents.

Your data stays yours. The cloud sees what you allow — nothing more.

## Why

AI coding agents (Claude Code, Codex, OpenCode, Hermes, Grok CLI) read your files,
logs, configs, and shell history — then send all of it to cloud LLM providers.
Your SSH keys, API tokens, user data, internal hostnames, and PII travel to
third-party servers on every agent request. No agent harness ships with a data
protection layer.

Tidegate fixes this. It's a local proxy that intercepts every LLM API call,
classifies the content, redacts sensitive data, and routes appropriately — cloud
models see scrubbed context, local Ollama handles anything that can't leave the
machine.

## Quick Start

### Option A — Install script (downloads release binary)

```bash
curl -fsSL https://raw.githubusercontent.com/qo-roj/tidegate/main/scripts/install.sh | bash
tidegate setup-ollama     # configure local model
tidegate start             # start gateway
tidegate install --all     # configure your agents
```

The script installs to `/usr/local/bin` when possible (writable, or
passwordless sudo; run it interactively with `--system` to use passworded
sudo) and falls back to `~/.local/bin`. If the fallback lands outside your
PATH, the installer **automatically** writes the PATH entry into your
shell's rc file (`~/.bashrc`, `~/.zshrc`, fish config) and `~/.profile` —
open a new terminal and it works. Pass `--no-path-edit` to keep the old
warn-only behavior.

### Option B — Build from source (requires Go 1.25+)

```bash
git clone https://github.com/qo-roj/tidegate.git
cd tidegate
make build
make install                # /usr/local/bin if writable, else ~/.local/bin
tidegate setup-ollama
tidegate start
tidegate install --all
```

### Option C — Docker

```bash
docker compose up -d        # starts Tidegate + Ollama
```

See `docker-compose.yml` and `config/tidegate.conf.example`.

## How It Works

```
Agent ──▶ Tidegate (localhost:8842) ──▶ ┌── Cloud API (scrubbed)
                                         └── Local Ollama (full data)
```

1. **Intercept** — agents route through Tidegate instead of hitting cloud APIs directly
2. **Classify** — content is tiered: public / redacted / local-only / blocked
3. **Redact** — IPs, emails, API keys, private keys, PII are replaced with tokens
4. **Route** — sensitive content goes to local Ollama, scrubbed content goes to cloud
5. **Audit** — every call logged with what was redacted, what went where

## Features

- **Gateway mode** — run one Tidegate on a server/Raspberry Pi for the whole LAN (`--bind 0.0.0.0` + client keys); any-OS clients just point their base URL at it, no local install — see [Gateway Mode](docs/gateway-mode.md)
- **Client authentication** — per-device pre-shared keys (`X-Tidegate-Key`, `tidegate keygen --add <name>`); key identity overrides the spoofable agent header; keys never reach cloud providers
- **Pattern redaction** — IPv4/IPv6, emails, phone numbers, API keys (GitHub, OpenAI, AWS, Anthropic, Google, Stripe, Slack, GitLab), JWTs, private keys, MAC addresses, credit cards, SSNs, database connection strings
- **`tidegate text`** — one-off redaction of text, files, or piped stdin for safe pasting into any web UI (ChatGPT, chatbots, tickets); `--out` writes a file, `--summary` lists what was caught
- **Agent auto-detection** — identifies agents by `X-Tidegate-Agent` header or `User-Agent` string (Claude Code, Codex, OpenCode, Hermes, Cursor, Aider, Cline, GitHub Copilot, Grok CLI)
- **Path-based rules** — block / local-only / redact entire directories
- **Two-model routing** — cloud for reasoning on scrubbed data, Ollama for sensitive data
- **Audit log** — SQLite-backed, full transparency, real-time monitoring (`--tail`, `--watch`), export and rotation
- **Presets** — desktop, server, paranoid, training-data (PII-safe fine-tuning) configurations out of the box
- **Per-project rules** — `.tidegate.conf` in any project root
- **Per-agent rules** — different agents get different access levels
- **TLS listener** — optional `--cert`/`--key` for HTTPS on untrusted networks
- **Docker support** — official `docker compose` setup with Ollama sidecar
- **CI/CD** — GitHub Actions with automated testing and cross-platform release binaries
- **Single binary** — Go, no runtime dependencies, cross-platform

## Documentation

- [Architecture](docs/architecture.md)
- [Gateway Mode](docs/gateway-mode.md)
- [Threat Model](docs/threat-model.md)
- [Rules Guide](docs/rules-guide.md)
- [Agent Setup](docs/agent-setup.md)

## License

MIT

## Authors

Earl & Sid 🦞🐚

*The tide comes in. The shell decides what stays.*