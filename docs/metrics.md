# Metrics

Tidegate exposes Prometheus text metrics and a JSON summary on a separate
listener, so scraping never shares a socket with proxied traffic.

```bash
tidegate start                      # default: 127.0.0.1:9116
tidegate start --metrics-addr 0.0.0.0:9116
tidegate start --no-metrics
```

- `/metrics` — Prometheus exposition
- `/stats` — JSON snapshot for dashboards and scripts

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tidegate_requests_total` | counter | `agent`, `provider` | Proxied LLM API requests |
| `tidegate_blocks_total` | counter | `tier` | Content blocks classified (`public`, `redacted`, `local-only`, `blocked`) |
| `tidegate_redactions_total` | counter | `pattern` | Values replaced, per pattern (`ipv4`, `email`, `json_secret`, …) |
| `tidegate_requests_blocked_total` | counter | — | Requests that contained blocked content |
| `tidegate_blocks_blocked_total` | counter | — | Individual blocks blocked |
| `tidegate_fail_closed_total` | counter | — | Requests refused because processing failed |
| `tidegate_upstream_errors_total` | counter | — | Failed upstream calls |
| `tidegate_redaction_cache_hits_total` | counter | — | Blocks served from the content-addressed cache |
| `tidegate_uptime_seconds` | gauge | — | Process uptime |
| `tidegate_vault_tokens` | gauge | — | Live token mappings |
| `tidegate_vault_cache_entries` | gauge | — | Live redaction-cache entries |

The headline number is **leaks prevented**: `tidegate_redactions_total` is
values that never left the machine, and `tidegate_blocks_*` is content refused
outright. Token savings are not a Tidegate metric.

## Prometheus

```yaml
scrape_configs:
  - job_name: tidegate
    static_configs:
      - targets: ["127.0.0.1:9116"]
```

## Gatus

```yaml
endpoints:
  - name: tidegate
    url: http://127.0.0.1:9116/stats
    conditions:
      - "[STATUS] == 200"
```

## Notes

- Counters are in-process and reset on restart. Durable history lives in the
  audit DB (`tidegate audit`).
- The default bind is loopback. Binding to a LAN address exposes operational
  data (agent names, pattern hit counts), not content — but keep it on a
  trusted network anyway.
- Label values are escaped per the Prometheus text format.
