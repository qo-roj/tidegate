package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTabularBlocksMetric(t *testing.T) {
	reg := New()
	reg.ObserveTabularBlocks(map[string]int{
		"tabular_blocks":        2,
		"shadow_tabular_blocks": 5,
	})
	reg.ObserveTabularBlocks(map[string]int{
		"tabular_blocks":       1,
		"tabular_email":        4,
		"tabular_ip":           2,
		"tabular_text":         0,
		"tabular_cols_dropped": 1,
	})
	// Tabular counters must not inflate the redaction headline.
	reg.ObserveRedactions(map[string]int{"tabular_email": 4, "email": 7})

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `tidegate_tabular_blocks_total{mode="apply"} 3`) {
		t.Errorf("apply counter missing:\n%s", body)
	}
	if !strings.Contains(body, `tidegate_tabular_blocks_total{mode="shadow"} 5`) {
		t.Errorf("shadow counter missing:\n%s", body)
	}
	if !strings.Contains(body, `tidegate_tabular_cells_total{mode="apply",kind="email"} 4`) {
		t.Errorf("per-kind cell counter missing:\n%s", body)
	}
	if strings.Contains(body, `kind="cols_dropped"`) {
		t.Errorf("dropped columns counted as generalized cells:\n%s", body)
	}
	if strings.Contains(body, `tidegate_redactions_total{pattern="tabular_email"}`) {
		t.Errorf("tabular cells leaked into the redaction counter:\n%s", body)
	}
	if !strings.Contains(body, `tidegate_redactions_total{pattern="email"} 7`) {
		t.Errorf("ordinary redaction counter wrong:\n%s", body)
	}

	stats := httptest.NewRecorder()
	reg.Handler().ServeHTTP(stats, httptest.NewRequest("GET", "/stats", nil))
	if !strings.Contains(stats.Body.String(), `"tabular_blocks":{"apply":3,"shadow":5}`) {
		t.Errorf("JSON stats missing counters:\n%s", stats.Body.String())
	}
}
