# Table generalization

Tidegate normally replaces sensitive values with tokens: `bob@example.com`
becomes `[TG:EMAIL:3]`, and the session vault can resolve it back. That is the
right trade for a token in a config file. It is the wrong trade for a data
table, because an agent asked to write analysis code needs the *shape* of the
data — columns, types, groupings, ranges — and tokens give it none of that.
The agent then writes code that has never been tested against anything
resembling the real table.

Table generalization gives the agent a data-shaped stand-in. The real values
never leave the machine, and the agent still gets:

- the same column names, order, count and data types
- the same row count and the same pattern of empty cells
- grouping and join keys that behave identically (same input → same label)
- ordering, magnitude and approximate distribution
- time intervals and weekday alignment
- parseable formats: email addresses with real domains, valid IP shapes

It is on by default in `shadow` mode: the gateway measures what it *would*
rewrite and forwards the ordinary redacted text. Nothing changes for the agent
until a preset or config sets `mode = apply`.

```
guest_id,full_name,email,ip_address,card_number,signup_date,nightly_rate
1,v2fa359,ua6f336@gmail.com,192.168.97.189,4**** **** **** 3243,2025-02-04,190.0
2,v18422b,u3de089@proton.me,192.168.230.168,5**** **** **** 6603,2025-02-05,210.0
3,vbc2726,u9652e3@example.org,10.0.101.24,4**** **** **** 0354,2025-02-15,150.0
```

## What it detects

CSV, TSV, semicolon-delimited output, and markdown tables. Detection is
deliberately conservative: a header row, at least `min_rows` data rows
(default 3), a consistent field count, and a non-numeric header are required.
Source-code-shaped blocks and prose are rejected rather than mangled. JSON
documents are not handled here — they take the JSON-key redaction path.

## Per-column treatment

| Column type | Output | Property preserved |
|---|---|---|
| email | `u<hash>@<real domain>` | domain distribution, per-address distinctness |
| IP address | `/16` prefix kept, host part hashed | subnet grouping, RFC 1918 status |
| card number | leading digit + masked + 4 hash digits | brand hint, distinctness, no Luhn-valid PAN |
| phone | country/area prefix + masked subscriber | dialling structure |
| UUID | same shape, hash-derived body | version/variant shape, distinctness |
| URL | scheme + hash host + hash path | it still parses as a URL |
| date | whole column shifted by a per-install ±182 day offset | intervals, weekday, ordering |
| int / float | rounded to `sig_figs` significant figures | ordering, magnitude, type |
| bool | untouched | exact spelling |
| text | salted label `v<hash>` | cardinality, grouping |

Labels are salted hashes, not sequence numbers. There is no mapping table and
no per-session state, so the same value produces the same label in turn 1 and
turn 50, even if the block is re-sent in a different row order. Joins and
`GROUP BY` behave the same as on the real data.

## What is deliberately lost

- absolute values: numbers, dates and identifiers are wrong
- absolute time anchor: shifted by a constant
- free text: labels unless `text = auto` or `text = keep` is set
- anything depending on the exact spelling of a value

**Never rehydrate a generalized cell.** A label is a placeholder for a value
the agent never saw, not a stand-in that can be swapped back. Generated code
that hard-codes a label should be treated as wrong, not as something the
gateway can fix.

## Modes

| `mode` | Behaviour |
|---|---|
| `off` | No detection, no rewrite. |
| `shadow` | Detect and generalize, count what would change, forward the normally redacted text. |
| `apply` | Rewrite the table; pattern redaction is skipped for that block. |

## Why pattern redaction is skipped in apply mode

Generalization runs before pattern redaction (patterns would otherwise turn
`bob@example.com` into `[TG:EMAIL:1]` and destroy type inference). In apply
mode the block is then returned without the pattern pass, because every cell
is already a label, a rounded number, a shifted date or a boolean — running
the PII regexes over them would only re-tokenize the labels and throw away
the structure the transform exists to preserve.

That guarantee depends on `text = hash`, which is the default: every text
column, including free-form notes, becomes a label. Setting `text = auto` (keep
high-cardinality free text readable) or `text = keep` (never touch text)
reintroduces raw cells that no longer get pattern coverage. The gateway prints
a warning at startup when either is combined with `apply`. Use `hash` for
anything regulated.

## Configuration

```toml
[tabular]
mode = "shadow"        # off | shadow | apply
min_rows = 3           # smallest table worth generalizing
sig_figs = 2           # significant figures kept in numeric columns
text = "hash"          # hash | auto | keep
max_categorical = 200  # text columns at or below this cardinality are hashed under "auto"
salt_file = "~/.config/tidegate/tabular.salt"
keep = []              # header regexes; non-empty means allowlist only
drop = ["card_number", "billing_address"]
disable = ["url"]      # email, ip, phone, card, ssn, uuid, url, date, number, text
```

The salt is generated on first use (32 random bytes, hex, `0600`, in a `0700`
directory). It is what stops a label from being a dictionary lookup on a known
address. Back it up with the config: with a new salt, labels change, and code
that hard-coded a label stops matching.

Presets: `desktop` ships `shadow`; `server`, `paranoid` and `training-data`
ship `apply` with `text = hash` (`paranoid` also uses `sig_figs = 1`).

## Metrics

```
tidegate_tabular_blocks_total{mode="apply"}  12
tidegate_tabular_blocks_total{mode="shadow"} 340
tidegate_tabular_cells_total{mode="apply",kind="email"} 96
```

Tabular counters are excluded from `tidegate_redactions_total`: a generalized
cell is rewritten, not replaced by a reversible token, and mixing the two
would inflate the headline leak count.

## Rollout

1. Leave `mode = shadow` and run normal traffic.
2. Compare `tidegate_tabular_blocks_total{mode="shadow"}` and the per-kind
   cells against your expectations for the agents you run.
3. Review a week of audit entries to see which tables would have changed.
4. Flip to `apply` per preset or per host, and watch agent code quality.

## Known limits

- row count is preserved, so table size is not hidden
- one-row and two-row results are not generalized (`min_rows`)
- tables embedded in fenced code blocks are not detected yet
- JSON arrays of records are not generalized
- a category with a very large number of distinct values still maps to a
  label, so the label count reveals the cardinality
