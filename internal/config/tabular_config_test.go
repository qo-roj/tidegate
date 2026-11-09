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
		{preset: "server", mode: "apply", text: "hash", sigFigs: 2, minRows: 3},
		{preset: "paranoid", mode: "apply", text: "hash", sigFigs: 1, minRows: 3},
		{preset: "training-data", mode: "apply", text: "hash", sigFigs: 2, minRows: 3},
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
