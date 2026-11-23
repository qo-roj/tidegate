package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTabularSectionParsing(t *testing.T) {
	cfg := &AppConfig{}
	applyGatewayBytes(cfg, []byte(`
[tabular]
mode = apply
min_rows = 5
sig_figs = 3
max_categorical = 50
text = hash
salt_file = /tmp/example.salt
keep = email, nights
drop = ^card_number$, ^billing_address$
disable = url, date
`))

	if cfg.Tabular.Mode != "apply" {
		t.Errorf("mode = %q", cfg.Tabular.Mode)
	}
	if cfg.Tabular.MinRows != 5 || cfg.Tabular.SigFigs != 3 || cfg.Tabular.MaxCategorical != 50 {
		t.Errorf("thresholds = %+v", cfg.Tabular)
	}
	if cfg.Tabular.Text != "hash" || cfg.Tabular.SaltFile != "/tmp/example.salt" {
		t.Errorf("text/salt = %+v", cfg.Tabular)
	}
	if len(cfg.Tabular.Keep) != 2 || cfg.Tabular.Keep[0] != "email" || cfg.Tabular.Keep[1] != "nights" {
		t.Errorf("keep = %v", cfg.Tabular.Keep)
	}
	if len(cfg.Tabular.Drop) != 2 || cfg.Tabular.Drop[0] != "^card_number$" {
		t.Errorf("drop = %v", cfg.Tabular.Drop)
	}
	if len(cfg.Tabular.Disable) != 2 || cfg.Tabular.Disable[1] != "date" {
		t.Errorf("disable = %v", cfg.Tabular.Disable)
	}

	opts := cfg.Tabular.Options()
	if !opts.Disable["url"] || !opts.Disable["date"] {
		t.Errorf("options disable = %v", opts.Disable)
	}
	if cfg.Tabular.ParsedMode().String() != "apply" {
		t.Errorf("parsed mode = %v", cfg.Tabular.ParsedMode())
	}
}

func TestTabularDefaultsAndPresets(t *testing.T) {
	cases := []struct {
		preset   string
		mode     string
		text     string
		sigFigs  int
		minRows  int
		wantText string
	}{
		{preset: "desktop", mode: "shadow", text: "hash", sigFigs: 2, minRows: 3},
		{preset: "server", mode: "shadow", text: "hash", sigFigs: 2, minRows: 3},
		{preset: "paranoid", mode: "shadow", text: "hash", sigFigs: 2, minRows: 3},
		{preset: "training-data", mode: "shadow", text: "hash", sigFigs: 2, minRows: 3},
	}

	for _, c := range cases {
		t.Run(c.preset, func(t *testing.T) {
			// Isolate from any real user config on the machine.
			t.Setenv("HOME", t.TempDir())
			cfg, err := Load(0, c.preset)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Tabular.Mode != c.mode {
				t.Errorf("mode = %q, want %q", cfg.Tabular.Mode, c.mode)
			}
			if cfg.Tabular.Text != c.text {
				t.Errorf("text = %q, want %q", cfg.Tabular.Text, c.text)
			}
			if cfg.Tabular.SigFigs != c.sigFigs {
				t.Errorf("sig_figs = %d, want %d", cfg.Tabular.SigFigs, c.sigFigs)
			}
			if cfg.Tabular.MinRows != c.minRows {
				t.Errorf("min_rows = %d, want %d", cfg.Tabular.MinRows, c.minRows)
			}
			if cfg.Tabular.SaltFile == "" {
				t.Error("salt_file is empty")
			}
		})
	}
}

func TestTabularUserConfigOverridesPreset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, filepath.Join(home, ".config", "tidegate", "tidegate.conf"),
		"[tabular]\nmode = off\nsig_figs = 4\n")

	cfg, err := Load(0, "server")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tabular.Mode != "off" {
		t.Errorf("user config did not override preset mode: %q", cfg.Tabular.Mode)
	}
	if cfg.Tabular.SigFigs != 4 {
		t.Errorf("user config did not override sig_figs: %d", cfg.Tabular.SigFigs)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestTabularValidateRejectsBadConfig(t *testing.T) {
	bad := []Tabular{
		{Mode: "sideways"},
		{Text: "plain"},
		{Disable: []string{"emails"}},
		{SaltFile: "relative/salt"},
		{Drop: []string{"("}},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted %+v", c)
		}
	}

	good := Tabular{Mode: "apply", Text: "hash", SaltFile: "/tmp/salt", Drop: []string{"^card$"}}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate rejected a valid section: %v", err)
	}
}

func TestTabularApplySafe(t *testing.T) {
	if err := (Tabular{Mode: "apply", Text: "auto"}).ApplySafe(); err == nil {
		t.Error("apply with text=auto must be refused")
	}
	if err := (Tabular{Mode: "apply", Text: "keep"}).ApplySafe(); err == nil {
		t.Error("apply with text=keep must be refused")
	}
	if err := (Tabular{Mode: "apply", Text: "hash", Disable: []string{"email"}}).ApplySafe(); err == nil {
		t.Error("apply with a disabled generalizer must be refused")
	}
	if err := (Tabular{Mode: "apply", Text: "hash"}).ApplySafe(); err != nil {
		t.Errorf("valid apply policy refused: %v", err)
	}
}

func TestExpandUserPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got := expandUserPath("~/x/salt"); got != filepath.Join(home, "x", "salt") {
		t.Errorf("expandUserPath = %q", got)
	}
	if got := expandUserPath("/absolute/salt"); got != "/absolute/salt" {
		t.Errorf("absolute path changed: %q", got)
	}
	if got := expandUserPath("relative"); got != "relative" {
		t.Errorf("relative path changed: %q", got)
	}
}

func TestLoadRejectsRelativeTabularSalt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, filepath.Join(home, ".config", "tidegate", "tidegate.conf"),
		"[tabular]\nmode = shadow\nsalt_file = relative.salt\n")
	if _, err := Load(0, "server"); err == nil {
		t.Fatal("Load accepted a relative salt_file")
	}
}

func TestLoadExpandsTildeSaltPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFile(t, filepath.Join(home, ".config", "tidegate", "tidegate.conf"),
		"[tabular]\nmode = shadow\nsalt_file = ~/.config/tidegate/salt.test\n")
	cfg, err := Load(0, "server")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := filepath.Join(home, ".config", "tidegate", "salt.test")
	if cfg.Tabular.SaltFile != want {
		t.Errorf("salt_file = %q, want %q", cfg.Tabular.SaltFile, want)
	}
}

func TestTabularAcceptsBracketLists(t *testing.T) {
	cfg := &AppConfig{}
	applyGatewayBytes(cfg, []byte(`
[tabular]
mode = shadow
keep = ["id", "email"]
drop = ["card_number"]
disable = ["url", "date"]
`))
	if len(cfg.Tabular.Keep) != 2 || cfg.Tabular.Keep[0] != "id" {
		t.Errorf("keep = %v", cfg.Tabular.Keep)
	}
	if len(cfg.Tabular.Drop) != 1 || cfg.Tabular.Drop[0] != "card_number" {
		t.Errorf("drop = %v", cfg.Tabular.Drop)
	}
	if len(cfg.Tabular.Disable) != 2 || cfg.Tabular.Disable[1] != "date" {
		t.Errorf("disable = %v", cfg.Tabular.Disable)
	}
	if err := cfg.Tabular.Validate(); err != nil {
		t.Errorf("bracket lists failed validation: %v", err)
	}

	// An empty bracket array is an empty list, not an invalid pattern.
	cfg2 := &AppConfig{}
	applyGatewayBytes(cfg2, []byte("[tabular]\nkeep = []\ndrop = []\n"))
	if err := cfg2.Tabular.Validate(); err != nil {
		t.Errorf("empty lists failed validation: %v", err)
	}
}

// TestTabularUnanchoredBracketRegexSurvives closes the round-2 MINOR: an
// unquoted value that merely STARTS with '[' (a regex character class) was
// silently stripped to its interior — `keep = [a-z]+_id` became `a-z]+_id`,
// which Go compiles (bare ']' is a literal) and silently matches nothing.
// Bracket stripping must fire only when the value is a full bracket list.
func TestTabularUnanchoredBracketRegexSurvives(t *testing.T) {
	// canonical comma form, unchanged
	if got := splitCSVList("url, card"); len(got) != 2 || got[0] != "url" || got[1] != "card" {
		t.Errorf("canonical comma form: %v", got)
	}
	// full bracket list (both ends): stripped, as documented
	if got := splitCSVList(`["url", "card"]`); len(got) != 2 || got[0] != "url" || got[1] != "card" {
		t.Errorf("full bracket list: %v", got)
	}
	if got := splitCSVList("[url, card]"); len(got) != 2 || got[0] != "url" {
		t.Errorf("unquoted bracket list: %v", got)
	}
	// unanchored bracket (regex character class): must survive BYTE-EXACT
	for _, re := range []string{`[a-z]+_id`, `[0-9]{3}`, `foo]bar`, `[]ab`} {
		if got := splitCSVList(re); len(got) != 1 || got[0] != re {
			t.Errorf("unanchored bracket value %q mangled to %v", re, got)
		}
	}
	// a value that IS a full bracket shape is a list; quoting forces the literal
	if got := splitCSVList(`"[0-9]"`); len(got) != 1 || got[0] != `[0-9]` {
		t.Errorf("quoted full-bracket regex: %v", got)
	}
	// matching quote pairs are trimmed; unmatched quotes survive
	if got := splitCSVList(`"url"`); len(got) != 1 || got[0] != "url" {
		t.Errorf("matching double quotes: %v", got)
	}
	if got := splitCSVList(`'url'`); len(got) != 1 || got[0] != "url" {
		t.Errorf("matching single quotes: %v", got)
	}
	if got := splitCSVList(`"foo'`); len(got) != 1 || got[0] != `"foo'` {
		t.Errorf("unmatched quotes must survive: %v", got)
	}
	// end-to-end: the keep regex survives a config load and still compiles
	cfg := &AppConfig{}
	applyGatewayBytes(cfg, []byte("[tabular]\nkeep = [a-z]+_id\n"))
	if len(cfg.Tabular.Keep) != 1 || cfg.Tabular.Keep[0] != `[a-z]+_id` {
		t.Fatalf("keep after config load = %v", cfg.Tabular.Keep)
	}
	if err := cfg.Tabular.Validate(); err != nil {
		t.Errorf("keep regex failed validation: %v", err)
	}
}
