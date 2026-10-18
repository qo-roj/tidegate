# Wrap & Unwrap

`tidegate wrap <agent>` points an agent CLI at the local gateway; `tidegate
unwrap <agent>` restores exactly what was there before.

## Supported agents

| Agent | Config file | What changes |
|---|---|---|
| `claude` | `~/.claude/settings.json` | `env.ANTHROPIC_BASE_URL` (+ `ANTHROPIC_AUTH_TOKEN` if `--key` given) |
| `codex` | `~/.codex/config.toml` | top-level `model_provider = "tidegate"` + `[model_providers.tidegate]` block |
| `opencode` | `~/.config/opencode/opencode.json` | `provider.tidegate` (OpenAI-compatible, `options.baseURL`) |
| `env` | — | prints shell exports, touches nothing |

```bash
tidegate wrap claude
tidegate wrap codex --key "$(pass show tidegate/gateway)"   # gateway mode
tidegate wrap --list
tidegate unwrap claude
```

Default URLs:

- `claude` → `http://127.0.0.1:8842/anthropic` (the Anthropic SDK appends
  `/v1/messages` itself)
- `codex`, `opencode`, `env` → `http://127.0.0.1:8842/openai/v1`

Override with `--base-url`. Use `--port` when the gateway does not run on 8842.

## Safety properties

- **Reversible** — prior values are recorded in
  `~/.config/tidegate/wrap.json` (mode `0600`); unwrap restores them, deletes
  keys that did not exist, and removes files that wrap created.
- **Non-destructive** — unrelated settings are preserved. A file's mode is
  restored on unwrap.
- **Refuses surprises** — if Codex already sets `model_provider`, wrap stops
  instead of writing invalid TOML.
- **Key handling** — `--key` writes the gateway key with mode `0600`. For
  Codex it becomes an `http_headers` entry; for Claude an
  `ANTHROPIC_AUTH_TOKEN`.
- **Marker blocks** — Codex edits are fenced with `# >>> tidegate >>>`
  comments, so `unwrap` can remove them even if the rest of the file changed.
  If the file was created by wrap and later edited beyond recognition, unwrap
  refuses rather than deleting it.

## Gateway mode

On a client machine with no Tidegate install, `wrap` still works — it only
edits client configuration:

```bash
tidegate wrap claude --base-url http://192.168.2.50:8842/anthropic --key "$KEY"
```

For agents with no supported config file, use the env target:

```bash
eval "$(tidegate wrap env --base-url http://192.168.2.50:8842/openai/v1 --key "$KEY")"
```
