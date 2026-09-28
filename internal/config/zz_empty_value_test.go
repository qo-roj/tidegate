package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Empty values must never override: a later file's `ollama_url =` (or a
// blank `bind =`) must not wipe a valid value set by an earlier file
// (dual-model review 2026-09-28 — both models flagged it).
func TestApplyGatewayFileEmptyValueDoesNotOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.conf")
	content := `
[gateway]
bind = 10.9.8.7

[local]
ollama_url =
ollama_model = ""
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Local.OllamaURL = "http://earlier:11434"
	cfg.Local.OllamaModel = "earlier-model"
	cfg.Gateway.Bind = "10.9.8.7"
	applyGatewayFile(cfg, path)
	if cfg.Local.OllamaURL != "http://earlier:11434" {
		t.Errorf("ollama_url = %q — empty value WIPED the earlier setting", cfg.Local.OllamaURL)
	}
	if cfg.Local.OllamaModel != "earlier-model" {
		t.Errorf("ollama_model = %q — empty quoted value WIPED the earlier setting", cfg.Local.OllamaModel)
	}
	if cfg.Gateway.Bind != "10.9.8.7" {
		t.Errorf("bind = %q, want unchanged", cfg.Gateway.Bind)
	}
}
