package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/config"
	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/tabular"
)

const cliTable = `guest,email,ip
Anna,anna.weber@gmail.com,192.168.2.14
Ben,ben.okafor@proton.me,192.168.2.87
Clara,clara@example.org,10.0.4.31
`

func TestRunTextHonoursTabularApply(t *testing.T) {
	opts := tabular.Options{Salt: "cli-test"}
	out, summary := runTextWith(cliTable, redact.New(), &opts, tabular.ModeApply)

	if strings.Contains(out, "anna.weber") || strings.Contains(out, "Anna") {
		t.Errorf("CLI apply mode left raw data:\n%s", out)
	}
	if !strings.Contains(out, "@gmail.com") {
		t.Errorf("CLI apply mode lost the domain:\n%s", out)
	}
	if summary["tabular_blocks"] != 1 {
		t.Errorf("tabular_blocks = %d, want 1", summary["tabular_blocks"])
	}
}

func TestRunTextHonoursTabularShadow(t *testing.T) {
	opts := tabular.Options{Salt: "cli-test"}
	out, summary := runTextWith(cliTable, redact.New(), &opts, tabular.ModeShadow)

	if !strings.Contains(out, "Anna") {
		t.Errorf("shadow mode rewrote the text:\n%s", out)
	}
	if summary["shadow_tabular_blocks"] != 1 {
		t.Errorf("shadow_tabular_blocks = %d, want 1", summary["shadow_tabular_blocks"])
	}
}

func TestRunTextWithoutTabularIsUnchanged(t *testing.T) {
	legacy, _ := runText(cliTable, redact.New())
	off, _ := runTextWith(cliTable, redact.New(), &tabular.Options{Salt: "cli-test"}, tabular.ModeOff)
	if legacy != off {
		t.Error("ModeOff differs from the legacy CLI path")
	}
}

func TestTabularApplyRefusesUnsafePolicy(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{Tabular: config.Tabular{
		Mode: "apply", Text: "keep", SaltFile: filepath.Join(dir, "salt"),
	}}
	if _, _, err := tabularOptions(cfg); err == nil {
		t.Fatal("apply + text=keep was accepted")
	}

	cfg.Tabular.Text = "hash"
	cfg.Tabular.Disable = []string{"email"}
	if _, _, err := tabularOptions(cfg); err == nil {
		t.Fatal("apply + disable=[email] was accepted")
	}

	cfg.Tabular.Disable = nil
	opts, mode, err := tabularOptions(cfg)
	if err != nil {
		t.Fatalf("valid apply policy refused: %v", err)
	}
	if mode != tabular.ModeApply || opts == nil || opts.Salt == "" {
		t.Fatalf("mode=%v opts=%+v", mode, opts)
	}
}
