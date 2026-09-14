# Gateway Mode — one Tidegate for the whole LAN

Tidegate normally runs on the same machine as the AI agents it protects
(single-machine mode, loopback only). **Gateway mode** runs one instance on a
server or Raspberry Pi that every machine on the LAN uses — Linux, Windows,
macOS, Android, anything with an HTTP client. No Tidegate install needed on
the clients: they just point their agent's API base URL at the gateway.

```
LAN client (any OS)                      gateway host (Pi / server)
┌──────────────────┐    LAN (or VPN)    ┌──────────────────────────┐
│ agent CLI        │ ──────────────────▶ │ tidegate start --bind …   │
│ base_url = …:8842│   X-Tidegate-Key    │  classify → redact → route │
└──────────────────┘                    │  audit log (one place)    │
                                        │  Ollama → cloud APIs     │
                                        └──────────────────────────┘
```

Why: release binaries exist for linux/darwin amd64+arm64 only, so Windows
and Android can't run Tidegate locally anyway — and every client gets the
same rules, the same audit trail, and zero redaction code on untrusted
devices. A phone that route leaks nothing: the secret it holds is only its
gateway key.

## Quick start

On the gateway host:

```bash
# 1. Create a client key per device (prints the key, appends to keyfile)
tidegate keygen --add phone        # → ~/.config/tidegate/clients.keys (0600)
tidegate keygen --add laptop

# 2. Serve the LAN
tidegate start --bind 0.0.0.0 --keyfile ~/.config/tidegate/clients.keys
```

On each client, point the agent at the gateway **and** send the key:

```bash
export OPENAI_BASE_URL="http://<gateway-ip>:8842/openai/v1"
export X_TIDEGATE_KEY="<client-key>"   # agent harnesses: send as header
```

For harnesses where you control headers directly (curl, custom code):

```bash
curl http://192.168.1.50:8842/openai/v1/chat/completions \
  -H "X-Tidegate-Key: <client-key>" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{...}'
```

`--bind 0.0.0.0` without any client keys is refused at startup. Gateway mode
requires authentication: without it, anyone on the LAN could burn your
cloud API keys or probe the redactor with crafted content.

## Path prefixes

Clients keep using the provider-prefixed paths (see README):

| Prefix | Upstream |
|---|---|
| `/anthropic` | api.anthropic.com |
| `/openai` | api.openai.com |
| `/xai` | api.x.ai |
| `/mistral` | api.mistral.ai |

## Client keys

Three ways to define them (can be combined; project config beats user
config beats keyfile for the same name):

1. **Keyfile** — `--keyfile <path>`, lines of `name key`, `#` comments,
   whitespace-separated. Generate with `tidegate keygen --add <name>`.
2. **Config sections** — in `~/.config/tidegate/tidegate.conf` or a
   project `.tidegate.conf`:
   ```ini
   [client:phone]
   key = "tg_5Kx9..."
   ```
3. Keys are 32-character base64url strings (24 random bytes) — copy them
   from the `keygen` output or the keyfile itself.

Requests authenticate with `X-Tidegate-Key: <key>`. The header is stripped
before forwarding upstream — cloud providers never see it. The client's
configured name becomes the agent identity in the audit log (it overrides
`X-Tidegate-Agent`, which is spoofable; the key is the only trusted
identity). `/health` stays open for monitoring.

Key management: keys are pre-shared secrets — distribute over a secure
channel (not plain chat). Rotate by removing the old line and adding a new
name+key. A keyfile with 0600 perms on the gateway is the only secret store.

## TLS (optional but recommended on untrusted networks)

Gateway mode is plain HTTP by default — fine on a home LAN or over
Tailscale/WireGuard, not fine on hostile Wi-Fi:

```bash
tidegate start --bind 0.0.0.0 --keyfile clients.keys \
  --cert cert.pem --key key.pem        # HTTPS listener
```

Or via config:

```ini
[gateway]
bind = 0.0.0.0
cert = /etc/tidegate/cert.pem
key  = /etc/tidegate/key.pem
```

The cert must be valid for whatever hostname/IP clients dial (SANs), or
clients must skip verification (curl `-k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
— acceptable when the client key already gates access).

## What changes for the operator

- **Audit log is central** — every client's requests land in the gateway's
  `~/.local/share/tidegate/audit.db`. `tidegate audit --live` on the
  gateway shows the whole LAN at once.
- **Rules are central** — the gateway's config/preset applies to everyone.
  Per-client differentiation: define clients named after the agent harness
  (`[client:claude-code]`) and use `[agent:claude-code]` rule sections;
  the client's key-name IS its agent identity in the rule engine.
- **Ollama must be reachable from the gateway** — point it at a real model
  server (`[local] ollama_url = http://r730:11434`), not localhost on the
  Pi, or `local-only` content gets blocked.
- **Client `.tidegate.conf` does not apply** — project-local rules are read
  from the gateway's working directory, not the client's. Put shared
  policy in the gateway's user config.

## Threat model notes

- The client's cloud API key still travels to the gateway (that's how
  pass-through works); on-path attackers see it unless TLS is enabled.
- The gateway key prevents *unauthorized use* of the gateway — a stolen
  gateway key lets the thief use *their own* cloud credits through your
  redactor; it does not expose your cloud keys.
- Bind to `127.0.0.1` + keys still works for loopback-only hardening
  (single-machine mode with auth on).

See `docs/threat-model.md` for the full model.