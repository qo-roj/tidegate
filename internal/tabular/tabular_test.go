package tabular

import (
	"strconv"
	"strings"
	"testing"

	"time"
)

const guestCSV = `guest_id,full_name,email,billing_address,card_number,ip_address,signup_date,nightly_rate,nights
1,Anna Weber,anna.weber@gmail.com,"Hauptstr. 12, Berlin",4111111111111111,192.168.2.14,2025-03-04,189.50,3
2,Ben Okafor,ben.okafor@proton.me,"12 High St, London",5500005555555559,192.168.2.87,2025-03-05,210.00,2
3,Clara Nunes,clara@example.org,"Rua A 4, Lisboa",4012888888881881,10.0.4.31,2025-04-11,145.25,5
4,Dieter Krause,d.krause@web.de,"Ring 8, Wien",3530111333300000,10.0.4.99,2025-04-12,95.00,1
`

func TestDetectCSV(t *testing.T) {
	tbl, ok := Detect(guestCSV)
	if !ok {
		t.Fatal("expected CSV to be detected")
	}
	if len(tbl.Header) != 9 {
		t.Fatalf("header cols = %d, want 9 (%v)", len(tbl.Header), tbl.Header)
	}
	if len(tbl.Rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(tbl.Rows))
	}
	if tbl.Header[2] != "email" {
		t.Fatalf("header[2] = %q", tbl.Header[2])
	}
	if !strings.Contains(tbl.Rows[0][3], "Berlin") {
		t.Fatalf("quoted field lost: %q", tbl.Rows[0][3])
	}
}

func TestDetectRejectsProse(t *testing.T) {
	prose := `Hi Earl, here is what I found when I looked at the backup job last night.
The cron entry runs at 03:30 and writes to the external disk, but the log line
suggests it failed twice this week with an exit code of 3, which restic uses to
mean that some files could not be read, so the backup itself is probably fine.
I would check permissions on the two directories it skipped before changing it.`
	if _, ok := Detect(prose); ok {
		t.Fatal("prose must not be detected as a table")
	}
}

func TestDetectRejectsCode(t *testing.T) {
	code := `func main() {
	cfg := load()
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}
func load() *Config {
	return &Config{Port: 8842}
}`
	if _, ok := Detect(code); ok {
		t.Fatal("source code must not be detected as a table")
	}
}

func TestGeneralizeRemovesDirectIdentifiers(t *testing.T) {
	// Different salt so the demo output is not this install's labels.
	res := Generalize(guestCSV, Options{Salt: "test-salt"})
	if !res.Applied {
		t.Fatal("expected table to be generalized")
	}
	out := res.Source
	for _, secret := range []string{"Anna Weber", "anna.weber", "ben.okafor", "clara@", "Hauptstr", "Rua A 4", "4111111111111111", "192.168.2.14"} {
		if strings.Contains(out, secret) {
			t.Errorf("output still contains %q", secret)
		}
	}
	for _, kept := range []string{"guest_id", "email", "signup_date", "nightly_rate", "@gmail.com", "@proton.me", "@example.org"} {
		if !strings.Contains(out, kept) {
			t.Errorf("output lost %q", kept)
		}
	}
	if res.Rows != 4 || res.Cols != 9 {
		t.Errorf("shape = %dx%d, want 4x9", res.Rows, res.Cols)
	}
	for _, k := range []string{"tabular_email", "tabular_card", "tabular_ip", "tabular_text", "tabular_date", "tabular_float"} {
		if res.Stats[k] == 0 {
			t.Errorf("stats missing %s: %v", k, res.Stats)
		}
	}
}

func TestGeneralizeIsStableAndOrderIndependent(t *testing.T) {
	a := Generalize(guestCSV, Options{Salt: "s"}).Source
	b := Generalize(guestCSV, Options{Salt: "s"}).Source
	if a != b {
		t.Fatal("same input must produce identical output")
	}

	// Reordering rows must not change any label: labels are hashes of the
	// value, not sequence numbers. Grouping and joins stay valid.
	lines := strings.Split(strings.TrimRight(guestCSV, "\n"), "\n")
	reordered := strings.Join([]string{lines[0], lines[3], lines[1], lines[4], lines[2]}, "\n") + "\n"
	c := Generalize(reordered, Options{Salt: "s"}).Source
	for _, want := range strings.Split(strings.TrimRight(a, "\n"), "\n")[1:] {
		if !strings.Contains(c, want) {
			t.Errorf("label row %q missing after reordering", want)
		}
	}

	// A different install salt must produce different labels.
	d := Generalize(guestCSV, Options{Salt: "other"}).Source
	if a == d {
		t.Fatal("different salts produced identical output")
	}
}

func TestIPSubnetPreserved(t *testing.T) {
	src := "host,ip,note\na,192.168.2.14,x\nb,192.168.2.87,y\nc,10.0.4.31,z\n"
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	var ips []string
	for _, line := range strings.Split(strings.TrimSpace(res.Source), "\n")[1:] {
		ips = append(ips, strings.Split(line, ",")[1])
	}
	if !strings.HasPrefix(ips[0], "192.168.") || !strings.HasPrefix(ips[1], "192.168.") {
		t.Errorf("subnet prefix lost: %v", ips)
	}
	if !strings.HasPrefix(ips[2], "10.0.") {
		t.Errorf("subnet prefix lost: %v", ips)
	}
	if ips[0] == ips[1] {
		t.Errorf("distinct hosts collapsed to one label: %v", ips)
	}
}

func TestDatesShiftButKeepIntervals(t *testing.T) {
	src := "id,day,amount\n1,2025-03-04,10\n2,2025-03-05,20\n3,2025-03-15,30\n"
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	rows := strings.Split(strings.TrimSpace(res.Source), "\n")[1:]
	var days []time.Time
	for _, r := range rows {
		f := strings.Split(r, ",")
		d, err := time.Parse("2006-01-02", f[1])
		if err != nil {
			t.Fatalf("bad date %q: %v", f[1], err)
		}
		days = append(days, d)
	}
	if days[1].Sub(days[0]) != 24*time.Hour {
		t.Errorf("one-day interval became %v", days[1].Sub(days[0]))
	}
	if days[2].Sub(days[1]) != 10*24*time.Hour {
		t.Errorf("ten-day interval became %v", days[2].Sub(days[1]))
	}
	if days[0].Format("2006-01-02") == "2025-03-04" {
		t.Error("date was not shifted at all")
	}
}

func TestNumbersKeepOrderAndMagnitude(t *testing.T) {
	src := "id,amount\n1,189.50\n2,210.00\n3,145.25\n4,95.00\n"
	res := Generalize(src, Options{Salt: "s", SigFigs: 2})
	rows := strings.Split(strings.TrimSpace(res.Source), "\n")[1:]
	var vals []float64
	for _, r := range rows {
		v, err := strconv.ParseFloat(strings.Split(r, ",")[1], 64)
		if err != nil {
			t.Fatalf("not a number: %q", r)
		}
		vals = append(vals, v)
	}
	if !(vals[0] > vals[2] && vals[1] > vals[0]) {
		t.Errorf("ordering broken: %v", vals)
	}
	for i, v := range vals {
		if v < 50 || v > 500 {
			t.Errorf("value %d left its order of magnitude: %v", i, v)
		}
	}
	if vals[0] == 189.50 {
		t.Error("value was not rounded")
	}
}

func TestNarrowDropsColumns(t *testing.T) {
	res := Generalize(guestCSV, Options{Salt: "s", Drop: []string{"^card_number$", "^billing_address$", "^full_name$"}})
	if !res.Applied {
		t.Fatal("expected table")
	}
	out := res.Source
	for _, gone := range []string{"card_number", "billing_address", "full_name", "Hauptstr"} {
		if strings.Contains(out, gone) {
			t.Errorf("dropped column still present: %q", gone)
		}
	}
	if res.Cols != 6 {
		t.Errorf("cols = %d, want 6", res.Cols)
	}
	if res.Stats["tabular_cols_dropped"] != 3 {
		t.Errorf("cols_dropped = %d, want 3", res.Stats["tabular_cols_dropped"])
	}
	if !strings.Contains(out, "nightly_rate") {
		t.Error("kept column disappeared")
	}

	keep := Generalize(guestCSV, Options{Salt: "s", Keep: []string{"email", "nights"}})
	if !keep.Applied || keep.Cols != 2 {
		t.Fatalf("keep policy: applied=%v cols=%d", keep.Applied, keep.Cols)
	}
}

func TestMarkdownTableRoundTrips(t *testing.T) {
	src := `| guest | email | nights |
|:------|:------|-------:|
| Anna Weber | anna.weber@gmail.com | 3 |
| Ben Okafor | ben.okafor@proton.me | 2 |
| Clara Nunes | clara@example.org | 5 |
`
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected markdown table to be detected")
	}
	out := res.Source
	sep := strings.Split(strings.TrimRight(out, "\n"), "\n")[1]
	if !strings.Contains(sep, "---") {
		t.Errorf("separator row lost:\n%s", out)
	}
	if strings.Contains(out, "Anna Weber") || strings.Contains(out, "anna.weber") {
		t.Errorf("PII survived:\n%s", out)
	}
	if !strings.Contains(out, "@gmail.com") {
		t.Errorf("domain lost:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			t.Errorf("row is not a markdown row: %q", line)
		}
	}
}

func TestSmallBlocksAreLeftAlone(t *testing.T) {
	src := "a,b\n1,2\n"
	if res := Generalize(src, Options{Salt: "s"}); res.Applied {
		t.Error("two-line block must not be treated as a table")
	}
}

func TestTSVAndSemicolon(t *testing.T) {
	tsv := "user\tmail\tnote\nu1\ta@b.com\tx\nu2\tc@d.org\ty\nu3\te@f.net\tz\n"
	if res := Generalize(tsv, Options{Salt: "s"}); !res.Applied || !strings.Contains(res.Source, "\t") {
		t.Fatalf("TSV not generalized:\n%s", res.Source)
	}
	sc := "user;mail\nu1;a@b.com\nu2;c@d.org\nu3;e@f.net\n"
	res := Generalize(sc, Options{Salt: "s"})
	if !res.Applied || !strings.Contains(res.Source, ";") {
		t.Fatalf("semicolon table not generalized:\n%s", res.Source)
	}
}

// ExampleGeneralize is the demo used in the design note. Run it with:
//
//	go test -run Example -v ./internal/tabular
func TestDemo(t *testing.T) {
	res := Generalize(guestCSV, Options{Salt: "demo"})
	t.Logf("applied=%v rows=%d cols=%d", res.Applied, res.Rows, res.Cols)
	t.Logf("\n%s", res.Source)
}
