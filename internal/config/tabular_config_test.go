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
