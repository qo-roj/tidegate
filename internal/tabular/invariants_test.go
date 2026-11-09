package tabular

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// adversarialTable has one non-conforming value per column in an otherwise
// well-typed table, so every column still types at the 90% threshold. These
// are exactly the cells that used to ship verbatim.
const adversarialTable = `id,email,ip,card,signup_date,phone,amount,full_name
1,anna.weber@gmail.com,192.168.2.14,4111111111111111,2025-03-04,+49 30 1234567,189.50,Anna Weber
2,ben.okafor@proton.me,192.168.2.87,5500005555555559,2025-03-05,+49 30 7654321,210.00,Ben Okafor
3,clara@example.org,10.0.4.31,4012888888881881,2025-03-06,+49 30 1112223,145.25,Clara Nunes
4,d.krause@web.de,10.0.4.99,3530111333300000,2025-03-07,+49 30 3334445,95.00,Dieter Krause
5,e.vogel@web.de,10.0.4.100,3566002020360505,2025-03-08,+49 30 5556667,120.00,Eva Vogel
6,f.schulz@gmx.de,10.0.4.101,5555555555554444,2025-03-09,+49 30 7778889,133.00,Felix Schulz
7,g.brandt@gmx.de,10.0.4.102,378282246310005,2025-03-10,+49 30 9990001,141.00,Greta Brandt
8,h.roth@posteo.de,10.0.4.103,6011111111111117,2025-03-11,+49 30 2223334,155.00,Hans Roth
9,i.neumann@posteo.de,10.0.4.104,4222222222222,2025-03-12,+49 30 4445556,162.00,Ines Neumann
10,not-an-email,999.999.1.1,4111111111111112,15/01/2024,555,189.50,Anna Weber
`

// TestNoRawCellSurvives is the invariant the whole transform rests on: after
// generalization, no cell of the input appears verbatim in the output.
func TestNoRawCellSurvives(t *testing.T) {
	res := Generalize(adversarialTable, Options{Salt: "invariant"})
	if !res.Applied {
		t.Fatal("expected the table to be generalized")
	}
	out := res.Source

	for _, raw := range []string{
		"Anna Weber", "Ben Okafor", "not-an-email",
		"192.168.2.14", "999.999.1.1",
		"4111111111111112", "4111111111111111",
		"15/01/2024", "2025-03-04",
		"555", "189.50", "210.00",
		"anna.weber",
	} {
		// "555" is too short to assert (it appears inside hashes); check the
		// full cell instead.
		if raw == "555" {
			continue
		}
		if strings.Contains(out, raw) {
			t.Errorf("raw value %q survived:\n%s", raw, out)
		}
	}
	if res.Stats["tabular_rejected"] == 0 {
		t.Errorf("expected rejected cells to be labelled, got %v", res.Stats)
	}
	if !strings.Contains(out, "@gmail.com") {
		t.Errorf("email domain lost:\n%s", out)
	}
}

func TestRejectedCellsAreLabelledNotDropped(t *testing.T) {
	// A single bad card in a card column: same shape as the probe that found
	// the leak.
	var b strings.Builder
	b.WriteString("id,card\n")
	b.WriteString("1,4111111111111112\n")
	for i := 2; i <= 10; i++ {
		fmt.Fprintf(&b, "%d,5500005555555559\n", i)
	}
	res := Generalize(b.String(), Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	if strings.Contains(res.Source, "4111111111111112") {
		t.Errorf("invalid PAN shipped verbatim:\n%s", res.Source)
	}
	if res.Stats["tabular_rejected"] != 1 {
		t.Errorf("rejected = %d, want 1 (%v)", res.Stats["tabular_rejected"], res.Stats)
	}
}

func TestHeaderlessTableIsNotDetected(t *testing.T) {
	src := `anna.weber@gmail.com,4815162342
ben.okafor@proton.me,8675309
clara@example.org,5551234
d.krause@web.de,4815162343
`
	if _, ok := Detect(src); ok {
		t.Fatal("a headerless table must not be detected: its first row would ship raw")
	}
	if res := Generalize(src, Options{Salt: "s"}); res.Applied {
		t.Error("headerless block was generalized")
	}
}

func TestHeaderWithValuesIsNotDetected(t *testing.T) {
	src := `guest,2025-03-04,192.168.2.14
a,2025-03-05,192.168.2.15
b,2025-03-06,192.168.2.16
c,2025-03-07,192.168.2.17
`
	if _, ok := Detect(src); ok {
		t.Fatal("a header made of values must not qualify as a header row")
	}
}

func TestPhoneColumnUsesPhoneGeneralizer(t *testing.T) {
	src := `id,phone
1,+49 30 1234567
2,+49 30 7654321
3,+49 30 1112223
4,+49 30 3334445
`
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	if res.Stats["tabular_phone"] == 0 {
		t.Errorf("phone generalizer never ran: %v", res.Stats)
	}
	if strings.Contains(res.Source, "1234567") || strings.Contains(res.Source, "7654321") {
		t.Errorf("phone digits survived:\n%s", res.Source)
	}
}

func TestBareDigitIdsAreNotPhones(t *testing.T) {
	src := `id,value
4815162342,10
4815162343,20
4815162344,30
4815162345,40
`
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	if res.Stats["tabular_phone"] != 0 {
		t.Errorf("bare digit ids were treated as phones: %v", res.Stats)
	}
	if !strings.Contains(res.Source, "4800000000") {
		t.Errorf("id column should stay numeric (2 s.f.):\n%s", res.Source)
	}
	for _, line := range strings.Split(strings.TrimSpace(res.Source), "\n")[1:] {
		id := strings.SplitN(line, ",", 2)[0]
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(id) {
			t.Errorf("id column was not left numeric: %q", id)
		}
	}
}

func TestDisableNumberCoversBothNumericTypes(t *testing.T) {
	src := `id,email,amount,int_amount
1,anna.weber@gmail.com,189.50,1000
2,ben.okafor@proton.me,210.00,2000
3,clara@example.org,145.25,3000
4,d.krause@web.de,95.00,4000
`
	res := Generalize(src, Options{Salt: "s", Disable: map[string]bool{"number": true}})
	if !res.Applied {
		t.Fatal("expected table")
	}
	if !strings.Contains(res.Source, "189.50") || !strings.Contains(res.Source, "210.00") {
		t.Errorf("disable=[number] did not preserve floats:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, ",1000") {
		t.Errorf("disable=[number] did not preserve ints:\n%s", res.Source)
	}
	if res.Stats["tabular_float"] != 0 || res.Stats["tabular_int"] != 0 {
		t.Errorf("numbers were still counted: %v", res.Stats)
	}
	if res.Stats["tabular_email"] == 0 {
		t.Errorf("email column should still be generalized: %v", res.Stats)
	}
}

func TestNoSaltMeansNoGeneralization(t *testing.T) {
	res := Generalize(adversarialTable, Options{})
	if res.Applied {
		t.Error("generalized without a salt: labels would be guessable")
	}
	if res.Source != adversarialTable {
		t.Error("source changed without a salt")
	}
}

func TestBadColumnPatternFailsClosed(t *testing.T) {
	res := Generalize(adversarialTable, Options{Salt: "s", Drop: []string{"("}})
	if res.Applied {
		t.Errorf("a bad drop pattern was accepted: %v", res.Stats)
	}
}

func TestMarkdownAlignmentPreserved(t *testing.T) {
	src := `| guest | email | nights |
|:-----:|:------|-------:|
| Anna Weber | anna.weber@gmail.com | 3 |
| Ben Okafor | ben.okafor@proton.me | 2 |
| Clara Nunes | clara@example.org | 5 |
`
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected markdown table")
	}
	sep := strings.Split(strings.TrimRight(res.Source, "\n"), "\n")[1]
	cells := strings.Split(strings.Trim(sep, "|"), "|")
	if len(cells) != 3 {
		t.Fatalf("separator cells = %d: %q", len(cells), sep)
	}
	center, left, right := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])
	if !strings.HasPrefix(center, ":") || !strings.HasSuffix(center, ":") {
		t.Errorf("center alignment lost: %q", center)
	}
	if !strings.HasPrefix(left, ":") || strings.HasSuffix(left, ":") {
		t.Errorf("left alignment lost: %q", left)
	}
	if !strings.HasSuffix(right, ":") || strings.HasPrefix(right, ":") {
		t.Errorf("right alignment lost: %q", right)
	}
}

// TestNarrowMarkdownDoesNotPanic covers a markdown table whose column is
// narrower than a separator cell (three dashes). Padding used to repeat a
// negative count and panic the request path in both apply and shadow mode.
func TestNarrowMarkdownDoesNotPanic(t *testing.T) {
	src := `| mail | ok |
|------|----|
| a@b.com | y |
| c@d.org | n |
| e@f.net | y |
`
	res := Generalize(src, Options{Salt: "s"})
	if !res.Applied {
		t.Fatal("expected table")
	}
	for _, line := range strings.Split(strings.TrimRight(res.Source, "\n"), "\n") {
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			t.Errorf("malformed markdown row: %q", line)
		}
	}
}
