// Package tabular generalizes table-shaped content — CSV, TSV, psql-style
// pipe output, markdown tables — so an agent can still write analysis code
// against it, while the real values never leave the machine.
//
// It is the structural counterpart to token redaction. Token redaction
// preserves identity (the vault can reverse [TG:EMAIL:3] later); tabular
// generalization is deliberately irreversible and instead preserves the
// properties an agent needs to write code that runs on the real data:
//
//   - column names, order, count and data types
//   - row count and nullability
//   - grouping and join keys (same input value → same label, always)
//   - ordering and magnitude (numbers are rounded to significant figures)
//   - intervals (dates shift by a constant per-install offset)
//   - distributions that matter for parsing (email domains, IP subnets)
//
// Labels are salted hashes, so the same value maps to the same label on
// every request without any per-session state, and no mapping is stored.
// There is nothing to rehydrate: a generalized cell is not a stand-in for a
// real value, it is a placeholder that keeps the code honest. Callers must
// never try to reverse it.
package tabular

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Options controls generalization. The zero value is usable and applies the
// defaults via withDefaults.
type Options struct {
	// Salt separates this install's labels from any other. Without it, a
	// label for a known value (a well-known email address, say) could be
	// computed by an attacker and matched. Empty means no generalization.
	Salt string
	// MinRows is the smallest number of data rows worth generalizing.
	MinRows int
	// SigFigs is how many significant figures numeric columns keep.
	SigFigs int
	// MaxCategorical is the largest number of distinct values for which a
	// free-text column is treated as categorical and labelled. Above it,
	// text is kept and left to pattern redaction.
	MaxCategorical int
	// Text is "hash" (default), "auto" or "keep". Hashing is the default
	// because it is the only setting under which no raw cell survives, and
	// the gateway can then skip pattern redaction on generalized tables.
	// "auto" keeps high-cardinality free text readable at the cost of that
	// guarantee; "keep" never touches text.
	Text string
	// Keep and Drop are header regexes (case-insensitive). Keep non-empty
	// means only matching columns survive. Dropped columns are removed, so
	// code written against the table cannot reference data it never saw.
	Keep []string
	Drop []string
	// Disable turns off individual generalizers by name: email, ip, phone,
	// card, ssn, uuid, url, date, number, text.
	Disable map[string]bool
}

// DefaultOptions is the policy the gateway uses unless configured otherwise.
func DefaultOptions() Options {
	return Options{MinRows: 3, SigFigs: 2, MaxCategorical: 200, Text: "hash"}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.MinRows <= 0 {
		o.MinRows = d.MinRows
	}
	if o.SigFigs <= 0 {
		o.SigFigs = d.SigFigs
	}
	if o.MaxCategorical <= 0 {
		o.MaxCategorical = d.MaxCategorical
	}
	if o.Text == "" {
		o.Text = d.Text
	}
	return o
}

// disabled reports whether the generalizer for a column type is switched off.
// "number" covers both numeric types, which is the name users see in config.
func (o Options) disabled(k colType) bool {
	if o.Disable[k.disableKey()] {
		return true
	}
	return o.Disable["number"] && (k == typeInt || k == typeFloat)
}

// Result is the outcome of generalizing one content block.
type Result struct {
	// Source is the rewritten block, or the input unchanged when Applied is
	// false.
	Source string
	// Applied reports whether the block was table-shaped and passed the
	// guards. Stats is empty when false.
	Applied bool
	// Rows and Cols describe the generalized table.
	Rows, Cols int
	// Stats counts generalized cells per kind, plus dropped columns. Keys
	// follow the redact.Summary style so they can be merged and audited.
	Stats map[string]int
}

// Table is a parsed delimited table.
type Table struct {
	Delim    rune
	Header   []string
	Rows     [][]string
	SepRow   []string // markdown separator row, re-emitted verbatim
	Markdown bool
}

// Generalize detects a table in src and rewrites its cells. When src is not
// a table, or the guards reject it, Result.Applied is false and Source is
// src. Without a salt nothing is generalized: labels would be computable.
func Generalize(src string, opt Options) Result {
	opt = opt.withDefaults()
	if opt.Salt == "" {
		return Result{Source: src}
	}
	t, ok := Detect(src)
	if !ok || len(t.Rows) < opt.MinRows {
		return Result{Source: src, Rows: 0, Cols: 0}
	}

	cols, dropped, err := t.narrow(opt)
	if err != nil || len(cols) == 0 {
		return Result{Source: src}
	}

	stats := map[string]int{}
	if dropped > 0 {
		stats["tabular_cols_dropped"] = dropped
	}

	// Headers are data too. A header cell that looks like a value is
	// labelled even though the stricter header heuristic should have
	// rejected such a block: defence in depth for headerless tables.
	for i, h := range t.Header {
		if headerLooksLikeValue(h) {
			t.Header[i] = reject(opt.Salt, h)
			stats["tabular_header"]++
		}
	}

	// One column at a time: types are inferred from the values, and date
	// shifting needs a single per-column offset so intervals survive.
	for ci := 0; ci < len(t.Header); ci++ {
		values := make([]string, 0, len(t.Rows))
		for _, row := range t.Rows {
			values = append(values, row[ci])
		}
		kind := infer(values)
		if opt.disabled(kind) {
			continue
		}
		changed, rejected := generalizeColumn(t.Header[ci], values, kind, opt)
		if changed > 0 {
			stats["tabular_"+kind.statKey()] += changed
		}
		if rejected > 0 {
			stats["tabular_rejected"] += rejected
		}
		for ri := range t.Rows {
			t.Rows[ri][ci] = values[ri]
		}
	}

	if len(stats) == 0 {
		return Result{Source: src}
	}
	out := t.render(len(cols))
	trail := strings.HasSuffix(src, "\n")
	out = strings.TrimRight(out, "\n")
	if trail {
		out += "\n"
	}
	return Result{Source: out, Applied: true, Rows: len(t.Rows), Cols: len(cols), Stats: stats}
}

// Detect parses a table out of src. It is conservative: a header row, at
// least three rows, consistent field counts and a non-numeric header are all
// required, and source-code-shaped blocks are rejected outright.
func Detect(src string) (*Table, bool) {
	if strings.TrimSpace(src) == "" {
		return nil, false
	}
	body := strings.TrimRight(src, "\r\n")
	lines := strings.Split(body, "\n")
	if len(lines) < 4 || looksLikeCode(lines) {
		return nil, false
	}

	var (
		best      *Table
		bestScore int
	)
	for _, d := range []rune{'|', '\t', ',', ';'} {
		t := parse(lines, d)
		if t == nil {
			continue
		}
		if score := len(t.Rows) * len(t.Header); score > bestScore {
			best, bestScore = t, score
		}
	}
	return best, best != nil
}

// parse attempts one delimiter. It returns nil when the lines are not a
// consistent table under that delimiter.
func parse(lines []string, d rune) *Table {
	t := &Table{Delim: d, Markdown: d == '|'}

	var recs [][]string
	if d == '|' {
		for _, ln := range lines {
			if !strings.Contains(ln, "|") {
				return nil
			}
			recs = append(recs, splitPipe(ln))
		}
	} else {
		r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
		r.Comma = d
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		r.TrimLeadingSpace = false
		out, err := r.ReadAll()
		if err != nil {
			return nil
		}
		recs = out
	}
	if len(recs) < 4 {
		return nil
	}

	n := len(recs[0])
	if n < 2 {
		return nil
	}
	for _, rec := range recs {
		if len(rec) != n {
			return nil
		}
	}

	// A markdown separator row is structure, not data.
	if t.Markdown {
		for i, rec := range recs {
			if isSepRow(rec) {
				t.SepRow = rec
				recs = append(recs[:i], recs[i+1:]...)
				break
			}
		}
		if t.SepRow == nil {
			return nil
		}
	} else if isSepRow(recs[0]) {
		return nil
	}

	if len(recs) < 4 {
		return nil
	}
	t.Header = recs[0]
	t.Rows = recs[1:]
	for _, c := range t.Header {
		if strings.TrimSpace(c) == "" || len(c) > 80 {
			return nil
		}
	}
	if !headerish(t.Header, t.Rows[0]) {
		return nil
	}
	return t
}

// splitPipe splits a markdown row on unescaped pipes, dropping the empty
// fields produced by leading/trailing pipes.
func splitPipe(line string) []string {
	s := strings.TrimSpace(line)
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '|':
			cur.WriteByte('|')
			i++
		case s[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	cells = append(cells, strings.TrimSpace(cur.String()))
	if len(cells) > 0 && cells[0] == "" && strings.HasPrefix(s, "|") {
		cells = cells[1:]
	}
	if len(cells) > 0 && cells[len(cells)-1] == "" && strings.HasSuffix(s, "|") {
		cells = cells[:len(cells)-1]
	}
	return cells
}

var sepCell = regexp.MustCompile(`^:?-{3,}:?$`)

func isSepRow(rec []string) bool {
	if len(rec) == 0 {
		return false
	}
	for _, c := range rec {
		if !sepCell.MatchString(strings.TrimSpace(c)) {
			return false
		}
	}
	return true
}

// headerish rejects blocks whose first row is data rather than a header — the
// main false-positive risk when a source file happens to be delimited, and the
// reason a headerless table must not reach the rewrite path. A real header is
// made of identifier-shaped words: no "@", no IPv4 dots, no URL scheme, no
// ISO date, and nothing that parses as a phone number or a card.
func headerish(header, firstRow []string) bool {
	letters := 0
	for i, c := range header {
		c = strings.TrimSpace(c)
		if c == "" || len(c) > 80 {
			return false
		}
		if !headerCellShaped(c) || headerLooksLikeValue(c) {
			return false
		}
		if strings.IndexFunc(c, func(r rune) bool {
			return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		}) >= 0 {
			letters++
		}
		if i < len(firstRow) && strings.EqualFold(c, strings.TrimSpace(firstRow[i])) {
			return false // header repeats the first data row
		}
	}
	return letters > 0
}

// headerCellShaped allows the punctuation real column names use and nothing
// that would be needed to spell an address, a URL or a timestamp.
func headerCellShaped(c string) bool {
	for _, r := range c {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(" _./%()#-", r):
		default:
			return false
		}
	}
	return true
}

// headerLooksLikeValue reports whether a cell is a personal value rather than
// a name for one.
func headerLooksLikeValue(c string) bool {
	c = strings.TrimSpace(c)
	if c == "" {
		return false
	}
	switch {
	case reEmail.MatchString(c), reUUID.MatchString(c), reSSN.MatchString(c), reURL.MatchString(c):
		return true
	case net.ParseIP(c) != nil:
		return true
	case isPhone(c), isLuhnCard(c):
		return true
	case !parseDate(c).IsZero():
		return true
	}
	return false
}

// isPhone requires a separator or a leading "+": a bare digit run is an
// integer id, not a phone number, and treating it as one would hash ids.
func isPhone(v string) bool {
	v = strings.TrimSpace(v)
	if !rePhone.MatchString(v) {
		return false
	}
	return strings.HasPrefix(v, "+") || strings.ContainsAny(v, " ()-.")
}

// looksLikeCode keeps tabular generalization away from source files that
// happen to parse as delimited text.
func looksLikeCode(lines []string) bool {
	hits := 0
	for _, ln := range lines {
		switch {
		case strings.Contains(ln, "func "), strings.Contains(ln, "def "),
			strings.Contains(ln, "<?php"), strings.Contains(ln, "#include"),
			strings.Contains(ln, "</"), strings.Contains(ln, "=>"),
			strings.HasSuffix(strings.TrimSpace(ln), ";") && strings.Contains(ln, "("),
			strings.HasSuffix(strings.TrimSpace(ln), "{") && strings.Contains(ln, "("):
			hits++
		}
	}
	return hits*10 >= len(lines)*3
}

// colType is the inferred shape of a column.
type colType int

const (
	typeText colType = iota
	typeInt
	typeFloat
	typeBool
	typeDate
	typeEmail
	typeIP
	typePhone
	typeUUID
	typeCard
	typeSSN
	typeURL
)

var (
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$`)
	reUUID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reSSN   = regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)
	reURL   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://\S+$`)
	rePhone = regexp.MustCompile(`^\+?[0-9][0-9 ()\-/. ]{5,}[0-9]$`)
	reCard  = regexp.MustCompile(`^[0-9](?:[0-9 \-]{9,23})[0-9]$`)
	reBool  = regexp.MustCompile(`^(?i:true|false|yes|no|y|n)$`)
)

var dateLayouts = []string{
	"2006-01-02",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"01/02/2006",
	"02.01.2006",
}

// infer picks the most specific type that at least 90% of non-empty values
// match.
func infer(values []string) colType {
	total := 0
	counts := map[colType]int{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		total++
		switch {
		case reEmail.MatchString(v):
			counts[typeEmail]++
		case reUUID.MatchString(v):
			counts[typeUUID]++
		case reSSN.MatchString(v):
			counts[typeSSN]++
		case reURL.MatchString(v):
			counts[typeURL]++
		case net.ParseIP(v) != nil:
			counts[typeIP]++
		case isLuhnCard(v):
			counts[typeCard]++
		case !parseDate(v).IsZero():
			counts[typeDate]++
		case reBool.MatchString(v):
			counts[typeBool]++
		case isPhone(v):
			counts[typePhone]++
		default:
			if _, err := strconv.ParseInt(v, 10, 64); err == nil {
				counts[typeInt]++
			} else if _, err := strconv.ParseFloat(v, 64); err == nil {
				counts[typeFloat]++
			}
		}
	}
	if total == 0 {
		return typeText
	}
	// Specific types win over numeric/text when they reach the threshold.
	for _, k := range []colType{typeEmail, typeUUID, typeSSN, typeURL, typeIP, typeCard, typeDate, typeBool, typePhone, typeInt, typeFloat} {
		if counts[k]*10 >= total*9 {
			return k
		}
	}
	return typeText
}

func isLuhnCard(v string) bool {
	if !reCard.MatchString(v) {
		return false
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, v)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func parseDate(v string) time.Time {
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// inferFromHeader reports whether a column name itself says the column holds
// personal data. Values in such a column are labelled even when they look
// like ordinary text.
func inferFromHeader(name string) bool {
	n := strings.ToLower(name)
	repl := strings.NewReplacer("_", " ", "-", " ", ".", " ")
	n = repl.Replace(n)
	for _, hint := range []string{
		"name", "surname", "given", "address", "street", "city", "town",
		"zip", "postal", "postcode", "email", "phone", "mobile", "card",
		"iban", "account", "ssn", "social security", "dob", "birth",
		"passport", "licence", "license", "guest", "customer", "patient",
	} {
		if strings.Contains(n, hint) {
			return true
		}
	}
	return false
}

// labelHex is the number of hex characters in a value label. Six hex
// characters (24 bits) collide by birthday around 5k distinct values, which
// merges entities in a large table; ten (40 bits) is safe well past any table
// an agent will paste into a prompt.
const labelHex = 10

// reject is the fail-closed fallback: a cell a typed generalizer could not
// handle becomes an opaque label instead of shipping verbatim. Losing the
// column's shape for one cell is acceptable; leaking it is not.
func reject(salt, v string) string { return label(salt, "v", v, labelHex) }

// generalizeColumn rewrites one column in place. It returns how many cells
// were generalized in the column's own type and how many fell back to an
// opaque label because they did not fit that type. In apply mode the caller
// relies on changed+rejected covering every non-empty cell.
func generalizeColumn(header string, values []string, kind colType, opt Options) (changed, rejected int) {
	switch kind {
	case typeEmail:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			local, domain, ok := strings.Cut(v, "@")
			if !ok || !reEmail.MatchString(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			// Domain is kept: it is the part analysis code groups by, and
			// the part that carries no identity on its own.
			values[i] = label(opt.Salt, "u", local, labelHex) + "@" + domain
			changed++
		}
	case typeIP:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			out, ok := generalizeIP(opt.Salt, v)
			if !ok {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			values[i] = out
			changed++
		}
	case typePhone:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !isPhone(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			// Keep the country/area prefix (dialling structure), replace
			// the subscriber number.
			prefix := ""
			if strings.HasPrefix(v, "+") {
				cut := strings.IndexAny(v[1:], " (")
				if cut > 0 {
					prefix = v[:cut+1]
				}
			}
			values[i] = prefix + " ***-**-" + digits(opt.Salt, v, 4)
			changed++
		}
	case typeCard:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !isLuhnCard(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			// Keep the leading digit (brand hint) and nothing else.
			values[i] = string(v[0]) + "**** **** **** " + digits(opt.Salt, v, 4)
			changed++
		}
	case typeSSN:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !reSSN.MatchString(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			values[i] = "***-**-" + digits(opt.Salt, v, 4)
			changed++
		}
	case typeUUID:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !reUUID.MatchString(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			h := hashBytes(opt.Salt, v)
			values[i] = fmt.Sprintf("%s-%s-4%s-8%s-%s",
				hex.EncodeToString(h[0:4]), hex.EncodeToString(h[4:6]),
				hex.EncodeToString(h[6:7]), hex.EncodeToString(h[7:8]),
				hex.EncodeToString(h[8:14]))
			changed++
		}
	case typeURL:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			scheme, _, ok := strings.Cut(v, "://")
			if !ok {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			values[i] = scheme + "://" + label(opt.Salt, "h", v, labelHex) + ".invalid/" + label(opt.Salt, "p", v, 4)
			changed++
		}
	case typeDate:
		off := dateOffset(opt.Salt)
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			t := parseDate(v)
			if t.IsZero() {
				// A cell that does not parse is still a value: label it
				// rather than ship it in a block that skips patterns.
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			shifted := t.AddDate(0, 0, off)
			values[i] = shifted.Format(layoutFor(v))
			changed++
		}
	case typeInt:
		for i, v := range values {
			trimmed := strings.TrimSpace(v)
			if trimmed == "" {
				continue
			}
			n, err := strconv.ParseInt(trimmed, 10, 64)
			if err != nil {
				// A float, a date or free text in an int column: label it
				// rather than ship it or silently truncate it.
				values[i], rejected = reject(opt.Salt, trimmed), rejected+1
				continue
			}
			rounded := strconv.FormatInt(int64(roundSig(float64(n), opt.SigFigs)), 10)
			if rounded != trimmed {
				changed++
			}
			values[i] = rounded
		}
	case typeFloat:
		for i, v := range values {
			trimmed := strings.TrimSpace(v)
			if trimmed == "" {
				continue
			}
			f, err := strconv.ParseFloat(trimmed, 64)
			if err != nil {
				values[i], rejected = reject(opt.Salt, trimmed), rejected+1
				continue
			}
			out := strconv.FormatFloat(roundSig(f, opt.SigFigs), 'f', -1, 64)
			// Keep the column's type visible: a float column whose values
			// all round to whole numbers must not start looking like an
			// integer column to the agent's parser.
			if !strings.ContainsAny(out, ".eE") {
				out += ".0"
			}
			if out != trimmed {
				changed++
			}
			values[i] = out
		}
	case typeBool:
		for i, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !reBool.MatchString(v) {
				values[i], rejected = reject(opt.Salt, v), rejected+1
				continue
			}
			// Booleans carry no identity and code needs their exact spelling.
		}
	case typeText:
		if opt.Text == "keep" {
			// Keep is a readability choice, only reachable in shadow mode:
			// apply refuses to start with anything but hash.
			return 0, 0
		}
		distinct := map[string]struct{}{}
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" {
				distinct[v] = struct{}{}
			}
		}
		sensitive := inferFromHeader(header)
		if opt.Text != "hash" && !sensitive && len(distinct) > opt.MaxCategorical {
			return 0, 0
		}
		for i, v := range values {
			if strings.TrimSpace(v) == "" {
				continue
			}
			values[i] = label(opt.Salt, "v", v, labelHex)
			changed++
		}
	}
	return changed, rejected
}

// generalizeIP keeps the network prefix and replaces the host part, so
// subnet grouping and "is it private" both survive.
func generalizeIP(salt, v string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return "", false
	}
	h := hashBytes(salt, v)
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[0], v4[1], h[0], h[1]), true
	}
	v6 := ip.To16()
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		if i < 2 {
			groups[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(v6[i*2:i*2+2]))
		} else {
			groups[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(h[i-2:i]))
		}
	}
	return strings.Join(groups, ":"), true
}

// dateOffset is a per-install constant in ±91 days and always a whole number
// of weeks, so intervals, weekday alignment and ordering all survive. A single
// offset for every date in the block is what makes the intervals exact; the
// absolute anchor is wrong by design.
func dateOffset(salt string) int {
	h := hashBytes(salt, "date-offset")
	return (int(binary.BigEndian.Uint16(h[:2]))%27)*7 - 91
}

func layoutFor(v string) string {
	for _, layout := range dateLayouts {
		if _, err := time.Parse(layout, v); err == nil {
			return layout
		}
	}
	return dateLayouts[0]
}

func roundSig(v float64, sig int) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	shift := float64(sig) - math.Ceil(math.Log10(math.Abs(v)))
	m := math.Pow(10, shift)
	return math.Round(v*m) / m
}

func hashBytes(salt, v string) []byte {
	sum := sha256.Sum256([]byte(salt + "\x00" + v))
	return sum[:]
}

// label builds a salted, stable placeholder of n hex characters.
func label(salt, prefix, v string, n int) string {
	return prefix + hex.EncodeToString(hashBytes(salt, v))[:n]
}

// digits builds a numeric placeholder of the requested length.
func digits(salt, v string, n int) string {
	h := hashBytes(salt, v)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = '0' + h[i]%10
	}
	return string(out)
}

func (t colType) statKey() string {
	switch t {
	case typeEmail:
		return "email"
	case typeIP:
		return "ip"
	case typePhone:
		return "phone"
	case typeUUID:
		return "uuid"
	case typeCard:
		return "card"
	case typeSSN:
		return "ssn"
	case typeURL:
		return "url"
	case typeDate:
		return "date"
	case typeInt:
		return "int"
	case typeFloat:
		return "float"
	case typeBool:
		return "bool"
	default:
		return "text"
	}
}

func (t colType) disableKey() string { return t.statKey() }

// narrow applies the Keep/Drop header policy. It returns the surviving
// column indexes and how many were removed.
func (t *Table) narrow(opt Options) ([]int, int, error) {
	keepRe, err := compileAll(opt.Keep)
	if err != nil {
		return nil, 0, err
	}
	dropRe, err := compileAll(opt.Drop)
	if err != nil {
		return nil, 0, err
	}

	var idx []int
	removed := 0
	for i, h := range t.Header {
		name := strings.TrimSpace(h)
		if len(keepRe) > 0 && !matchAny(keepRe, name) {
			removed++
			continue
		}
		if matchAny(dropRe, name) {
			removed++
			continue
		}
		idx = append(idx, i)
	}
	if removed == 0 {
		return idx, 0, nil
	}
	header := make([]string, len(idx))
	rows := make([][]string, len(t.Rows))
	for n, i := range idx {
		header[n] = t.Header[i]
	}
	for r := range t.Rows {
		row := make([]string, len(idx))
		for n, i := range idx {
			row[n] = t.Rows[r][i]
		}
		rows[r] = row
	}
	t.Header, t.Rows = header, rows
	if t.SepRow != nil {
		sep := make([]string, len(idx))
		for n, i := range idx {
			if i < len(t.SepRow) {
				sep[n] = t.SepRow[i]
			}
		}
		t.SepRow = sep
	}
	return idx, removed, nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid column pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func matchAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// render serializes the narrowed table, restoring the markdown layout when
// the input had one.
func (t *Table) render(cols int) string {
	if t.Markdown {
		return t.renderMarkdown(cols)
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.Comma = t.Delim
	_ = w.Write(t.Header)
	for _, row := range t.Rows {
		_ = w.Write(row)
	}
	w.Flush()
	return b.String()
}

func (t *Table) renderMarkdown(cols int) string {
	widths := make([]int, cols)
	for i, c := range t.Header {
		widths[i] = max(widths[i], len(c))
	}
	for _, row := range t.Rows {
		for i, c := range row {
			widths[i] = max(widths[i], len(c))
		}
	}
	// A markdown separator cell is at least three characters wide. Clamp the
	// column widths to match: otherwise a two-character column produces a
	// three-character separator and the padding below repeats a negative
	// count, panicking the request path.
	for i := range widths {
		widths[i] = max(widths[i], 3)
	}
	var b strings.Builder
	writeRow := func(cells []string) {
		b.WriteString("|")
		for i, c := range cells {
			b.WriteString(" ")
			b.WriteString(c)
			b.WriteString(strings.Repeat(" ", widths[i]-len(c)))
			b.WriteString(" |")
		}
		b.WriteString("\n")
	}
	writeRow(t.Header)
	if t.SepRow != nil {
		sep := make([]string, cols)
		for i := range sep {
			w := widths[i]
			left := strings.HasPrefix(strings.TrimSpace(t.SepRow[i]), ":")
			right := strings.HasSuffix(strings.TrimSpace(t.SepRow[i]), ":")
			switch {
			case left && right && w >= 3:
				sep[i] = ":" + strings.Repeat("-", w-2) + ":"
			case left:
				sep[i] = ":" + strings.Repeat("-", w-1)
			case right:
				sep[i] = strings.Repeat("-", w-1) + ":"
			default:
				sep[i] = strings.Repeat("-", w)
			}
		}
		writeRow(sep)
	}
	for _, row := range t.Rows {
		writeRow(row)
	}
	return b.String()
}
