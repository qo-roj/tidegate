# Tabular generalization — spike and wiring plan

Status: implemented on `feat/tabular-generalization`. Package, config,
router wiring, metrics, CLI parity and presets are done; full suite green
under `-race`. Two decisions changed during implementation, both recorded
below: the default text policy became `hash`, and pattern redaction is
skipped for generalized blocks.

## Why

Tidegate's redaction is identity-preserving: `[TG:EMAIL:3]` is reversible
through the session vault, so a value redacted in turn 1 can be restored in
turn 5. That is the right tool for a token in a config file. It is the wrong
tool for a data table: after redaction the agent still knows that `email` is
an email column, but has no addresses to group, count, join or validate a
parser against — so the analysis code it writes is guesswork that fails on
the real data.

The idea borrowed from the synthetic-data proxy workflow (SDV → cloud agent →
run locally) is to give the agent a **data-shaped stand-in** instead of
opaque tokens. We keep the useful part and drop the expensive part:

- keep: same columns, types, row count, grouping keys, ordering, intervals
- drop: SDV, Python, Gaussian copulas, and any pretence of statistical
  fidelity beyond marginals

## What the spike does

`internal/tabular` detects CSV, TSV, semicolon and markdown tables and
rewrites cells by inferred column type. Real output (`go test -run TestDemo
-v ./internal/tabular`, salt `demo`):

```
guest_id,full_name,email,billing_address,card_number,ip_address,signup_date,nightly_rate,nights
1,ve52d2d,u8955ad@gmail.com,v7d0224,4**** **** **** 4362,192.168.91.249,2025-06-02,190.0,3
2,v63f956,u11f256@proton.me,vf3d1e2,5**** **** **** 2968,192.168.204.233,2025-06-03,210.0,2
3,v11c1af,u5c64be@example.org,veff350,4**** **** **** 8696,10.0.206.90,2025-07-10,150.0,5
4,v0a0f70,uf7a492@web.de,v86770b,3**** **** **** 3799,10.0.43.236,2025-07-11,95.0,1
```

What survived on purpose:

| column | treatment | property kept |
|---|---|---|
| `guest_id` | untouched (ints round to 2 s.f.) | join key |
| `full_name`, `billing_address` | salted label `v<hash>` | cardinality, grouping |
| `email` | local part → `u<hash>`, domain kept | domain distribution, per-customer distinctness |
| `card_number` | leading digit + masked, 4 hash digits | brand hint, distinctness, no Luhn-valid PAN |
| `ip_address` | /16 prefix kept, host part hashed | subnet grouping, RFC1918 status |
| `signup_date` | whole column shifted by one per-install offset | intervals, weekday alignment, ordering |
| `nightly_rate` | rounded to 2 significant figures | ordering, magnitude, float type (`.0` kept) |
| `nights` | 1–2 digit ints unchanged at 2 s.f. | exact for coding |

Properties the tests pin down:

- deterministic: same value → same label, independent of row order, so joins
  and `GROUP BY` behave identically across turns
- salted: a different install salt yields different labels, so labels cannot
  be dictionary-attacked
- guards: prose, source code, tables under 3 data rows, and inconsistent field
  counts are rejected rather than mangled
- markdown tables round-trip with the separator row intact

## Design decisions

**No vault, no rehydration.** Generalization is irreversible by construction.
This is the opposite of the token vault and must stay that way: if a
generalized cell could be reversed, an agent that bakes a label into generated
SQL (`WHERE email = 'u8955ad'`) would silently rehydrate to a *different*
value's semantics. Labels are placeholders, never stand-ins.

**Labels are salted hashes, not sequence numbers.** No per-session state, no
mapping table, stable across turns even when the block is re-sent. The cost is
that two installs disagree on labels, which is correct.

**Dates shift by a constant per install, not per value.** Per-value shifting
would destroy intervals and make every time-series question unanswerable.
The absolute anchor is wrong by design; relative analysis still works.

**No synthesis.** Copulas buy correlation between columns, which matters for
"is this dataset realistic" and almost never for "write me the pandas code".
Marginals plus type fidelity are enough for codegen, and cost ~600 lines of
stdlib Go instead of a Python sidecar.

**Text policy is `auto`.** Label a text column when it has ≤200 distinct
values or its header says it is personal (`name`, `address`, `city`, `dob`,
…). Above that, leave it and let pattern redaction handle embedded emails and
phones. `text = keep` and `text = hash` override.

**Numbers round to significant figures, not to bins.** Rounding preserves
ordering, range and distribution shape without inventing bucket edges the
real data does not have.

## Config shape

New section in `internal/config/config.go` (the parser is
section/key/value, so this is mechanical):

```toml
[tabular]
mode = "shadow"        # off | shadow | apply   (default: shadow)
min_rows = 3
sig_figs = 2
text = "auto"          # auto | keep | hash
max_categorical = 200
salt = ""              # generated on first run if empty, stored 0600
keep = []              # header regexes; non-empty = allowlist
drop = ["card_number", "billing_address"]
disable = ["url"]      # generalizers to skip: email, ip, phone, card,
                       # ssn, uuid, url, date, number, text
```

`mode = shadow` classifies, generalizes and logs/audits what *would* have
changed, but forwards the original bytes. This is the rollout mechanism: a
week of shadow data on the real fleet tells us whether agents actually keep
producing working code, without risking a single degraded answer.

`Config` gets a `Tabular tabular.Settings` field; `rules.Config` does not need
to change because this is not a path rule.

## Integration

Single insertion point, `internal/route/router.go:297` (`ApplyShapeRedaction`),
which is already the shared surface for the proxy and `tidegate text`:

1. JSON-key redaction (existing) — leave first: it catches secrets by key.
2. **new** `tabular.Generalize(work, opts)` — only when
   `content.Detect(src) != content.KindJSON`, and only when
   `result.Applied`.
   - `mode = shadow`: merge `result.Stats` into the summary with a `shadow_`
     prefix and keep `work`.
   - `mode = apply`: replace `work` with `result.Source`.
3. timestamp shield + pattern redaction (existing) — must run *after*
   generalization, so cells below the inference threshold and free text left
   by `text = auto` still get pattern coverage. Running patterns first would
   turn emails into `[TG:EMAIL:1]` and destroy type inference.

`ctx.Summary` keys (`tabular_email`, `tabular_card`, `tabular_ip`,
`tabular_date`, `tabular_float`, `tabular_text`, `tabular_cols_dropped`)
flow into `s.Metrics.ObserveRedactions(ctx.Summary)` at
`internal/proxy/server.go:281` with no extra plumbing, and into the audit
entry's `Redactions` field at `router.go:258`.

`ProcessRequestSession` needs no change: generalization is stateless, so the
"only new messages are classified" fast path stays valid. Re-sent history is
forwarded byte-for-byte, exactly as today.

## Tasks

1. **Config plumbing** — add `[tabular]` parsing + `Config.Tabular`, default
   `mode = shadow`. Test: `internal/config/config_e2e_test.go`-style load.
2. **Salt lifecycle** — generate 32 random bytes on first run, store at
   `~/.config/tidegate/tabular.salt` (`0600`), never log it. Without this the
   default salt makes labels computable for known values.
3. **Wire `ApplyShapeRedaction`** — shadow + apply paths, skip JSON blocks,
   merge stats. Tests in `internal/route/router_test.go`: a CSV block passes
   through untouched in shadow, rewritten in apply, and a code block is never
   detected.
4. **Audit + metrics** — confirm `tabular_*` labels appear in
   `/metrics` output; add a `tabular_applied_total` / `tabular_shadow_total`
   counter pair in `internal/metrics/metrics.go` so the rollout can be judged
   without reading audit logs.
5. **`tidegate text` parity** — the CLI path shares `ApplyShapeRedaction`, so
   verify it honours mode (manual dry-run surface worth keeping).
6. **Docs** — `docs/tabular.md` (threat model, what is preserved, what must
   never be rehydrated), README feature bullet, `docs/design-decisions.md`
   entry for "why generalization is irreversible".
7. **Presets** — `server.conf` and `training-data.conf` opt into
   `mode = apply`; `desktop.conf` stays `shadow`; `paranoid.conf` gets
   `text = hash` and `sig_figs = 1`.

Deferred, deliberately: JSON arrays of records (`[{...}, {...}]`), SQL result
sets inside tool-call payloads, and CSV embedded in fenced code blocks. All
three are detection variants of the same transform; do them after the shadow
data says the transform is worth having.

## Open questions

- **Row-count leak.** Preserving the row count tells the agent how many
  customers there are. That is usually harmless and sometimes essential
  (sampling code, `head`/`tail` logic). Confirm before coarsening it.
- **`text = auto` and free-text notes.** Pattern redaction is the safety net
  there, but a name written in a comment field will survive. If that matters
  more than utility, `text = hash` is the strict answer.
- **Threshold at 3 rows.** psql output of a single row is not generalized;
  that row may still be sensitive. Consider generalizing any table with ≥1
  row when the header policy marks it personal — at the cost of mangling
  one-line CSV payloads.

## Implementation notes (post-spike)

Three things changed from the sketch above, all recorded in the code comments:

1. **Default `text` is `hash`, not `auto`.** Skipping pattern redaction on a
   generalized block is only safe if no raw cell survives, and `auto` leaves
   high-cardinality free text in place. `auto` and `keep` remain available for
   readability, with a startup warning when combined with `apply`.
2. **Pattern redaction is skipped for generalized blocks** (apply mode only).
   Running it afterwards re-tokenized every label. Shadow mode is unaffected.
3. **Presets are embedded from a copy**, `internal/config/rules/`, because
   `go:embed` cannot reference a parent directory. `rules/` at the repo root is
   the documented source. `TestEmbeddedRulesMatchSourceTree` now fails the
   build when the two drift — they had silently diverged before this work.

Also added: `tidegate_tabular_cells_total{mode,kind}` and tabular counters
excluded from `tidegate_redactions_total` (a generalized cell is not a
redaction), plus the redaction-cache fingerprint now includes the tabular
policy so a salt or threshold change cannot serve stale output.

## Review round (post-block)

Sid's probe review blocked the first wiring. Fixes applied in the same branch:

- fail-closed per cell: a typed generalizer that rejects a value labels it
  instead of forwarding it, counted as `tabular_rejected`
- stricter header heuristic plus value-shaped header labelling; headerless
  tables no longer qualify
- `apply` refuses unless `text = hash` and `disable` is empty
- `typePhone` is reachable (it was missing from the winner list) and no longer
  swallows bare digit ids; `disable = ["number"]` maps to int and float
- salt path expands `~` and must be absolute; unreadable or group-readable
  salts are fatal; the built-in default salt is gone
- labels widened to 10 hex, policy fingerprint JSON-encoded with a version
  marker, date offset a whole number of weeks
- invalid column patterns fail at config load; dropped columns no longer
  counted as generalized cells; markdown alignment preserved
- presets back to `shadow` for this release train
