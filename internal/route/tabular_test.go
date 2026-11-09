package route

import (
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/rules"
	"github.com/qo-roj/tidegate/internal/tabular"
)

const guestTable = `guest_id,full_name,email,ip_address,card_number,amount
1,Anna Weber,anna.weber@gmail.com,192.168.2.14,4111111111111111,189.50
2,Ben Okafor,ben.okafor@proton.me,192.168.2.87,5500005555555559,210.00
3,Clara Nunes,clara@example.org,10.0.4.31,4012888888881881,145.25
`

func TestTabularApplyRewritesTable(t *testing.T) {
	opts := tabular.Options{Salt: "route-test"}
	out, summary := ApplyShapeRedactionWith(guestTable, redact.New(), &opts, tabular.ModeApply)

	for _, leak := range []string{"Anna Weber", "anna.weber", "ben.okafor", "192.168.2.14", "4111111111111111"} {
		if strings.Contains(out, leak) {
			t.Errorf("output still contains %q:\n%s", leak, out)
		}
	}
	// The structure is the point: the domain survives, as a label not a token.
	if !strings.Contains(out, "@gmail.com") {
		t.Errorf("email domain lost:\n%s", out)
	}
	if strings.Contains(out, "[TG:") {
		t.Errorf("pattern redaction ran over a generalized table:\n%s", out)
	}
	if summary["tabular_blocks"] != 1 {
		t.Errorf("tabular_blocks = %d, want 1 (%v)", summary["tabular_blocks"], summary)
	}
	if summary["tabular_email"] == 0 || summary["tabular_ip"] == 0 || summary["tabular_card"] == 0 {
		t.Errorf("per-kind counters missing: %v", summary)
	}
	if _, ran := summary["email"]; ran {
		t.Errorf("pattern email counter present, patterns should be skipped: %v", summary)
	}
}

func TestTabularShadowMeasuresWithoutRewriting(t *testing.T) {
	opts := tabular.Options{Salt: "route-test"}
	out, summary := ApplyShapeRedactionWith(guestTable, redact.New(), &opts, tabular.ModeShadow)

	// Shadow forwards the block into the ordinary redaction path: names
	// survive, emails become tokens, nothing is generalized.
	if !strings.Contains(out, "Anna Weber") {
		t.Errorf("shadow mode changed the text:\n%s", out)
	}
	if !strings.Contains(out, "[TG:EMAIL") {
		t.Errorf("shadow mode skipped ordinary redaction:\n%s", out)
	}
	if strings.Contains(out, "@gmail.com") {
		t.Errorf("shadow mode generalized the table:\n%s", out)
	}
	if summary["shadow_tabular_blocks"] != 1 {
		t.Errorf("shadow_tabular_blocks = %d, want 1 (%v)", summary["shadow_tabular_blocks"], summary)
	}
	if summary["tabular_blocks"] != 0 {
		t.Errorf("shadow mode counted applied blocks: %v", summary)
	}
	if summary["shadow_tabular_email"] == 0 {
		t.Errorf("shadow per-kind counters missing: %v", summary)
	}
}

func TestTabularLeavesJSONAlone(t *testing.T) {
	src := `[{"host":"a","ip":"10.0.0.1"},{"host":"b","ip":"10.0.0.2"},{"host":"c","ip":"10.0.0.3"}]`
	opts := tabular.Options{Salt: "route-test"}
	out, summary := ApplyShapeRedactionWith(src, redact.New(), &opts, tabular.ModeApply)

	// JSON takes the key-redaction path and then ordinary pattern redaction;
	// it must not be treated as a table and must not skip patterns.
	if !strings.Contains(out, "[TG:") {
		t.Errorf("JSON block skipped pattern redaction:\n%s", out)
	}
	if summary["tabular_blocks"] != 0 {
		t.Errorf("JSON counted as a generalized table: %v", summary)
	}
}

func TestTabularOffIsUnchanged(t *testing.T) {
	opts := tabular.Options{Salt: "route-test"}
	off, offSummary := ApplyShapeRedactionWith(guestTable, redact.New(), &opts, tabular.ModeOff)
	legacy, legacySummary := ApplyShapeRedaction(guestTable, redact.New())

	if off != legacy {
		t.Error("ModeOff differs from the legacy path")
	}
	if len(offSummary) != len(legacySummary) {
		t.Errorf("ModeOff summary differs: %v vs %v", offSummary, legacySummary)
	}
	if offSummary["tabular_blocks"] != 0 || offSummary["shadow_tabular_blocks"] != 0 {
		t.Errorf("ModeOff counted blocks: %v", offSummary)
	}
}

func TestWithTabularChangesCacheFingerprint(t *testing.T) {
	rs := rules.BuildRuleSet(&rules.Config{}, "test")
	plain := New(rs, nil, nil)
	a := New(rs, nil, nil).WithTabular(tabular.Options{Salt: "a"}, tabular.ModeShadow)
	a2 := New(rs, nil, nil).WithTabular(tabular.Options{Salt: "a"}, tabular.ModeShadow)
	b := New(rs, nil, nil).WithTabular(tabular.Options{Salt: "b"}, tabular.ModeShadow)
	apply := New(rs, nil, nil).WithTabular(tabular.Options{Salt: "a"}, tabular.ModeApply)

	if a.rulesetFingerprint == plain.rulesetFingerprint {
		t.Error("enabling tabular did not change the cache fingerprint")
	}
	if a.rulesetFingerprint != a2.rulesetFingerprint {
		t.Error("identical policies produced different fingerprints")
	}
	if a.rulesetFingerprint == b.rulesetFingerprint {
		t.Error("salt change did not change the fingerprint")
	}
	if a.rulesetFingerprint == apply.rulesetFingerprint {
		t.Error("mode change did not change the fingerprint")
	}
}
