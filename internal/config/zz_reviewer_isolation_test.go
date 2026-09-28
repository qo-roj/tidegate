package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Reviewer-verification tests (2026-09-28 review round): pin the section
// state machine against mistral-large-2512's claimed "section leak" and the
// claimed '=' truncation. If these ever fail, the reviewers were right.
func TestReviewerClaimsSectionIsolation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.conf")
	content := `
[gateway]
bind = 10.1.2.3

[client:phone]
key = secret123
bind = 0.0.0.0
ollama_url = http://evil:11434
port = 1

[redaction]
ollama_url = http://also-evil:11434

[local]
ollama_url = http://good:11434?x=1=y
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Local.OllamaURL = "http://localhost:11434"
	applyGatewayFile(cfg, path)
	if cfg.Gateway.Bind != "10.1.2.3" {
		t.Errorf("bind = %q — [client:] keys LEAKED into gateway (reviewer was right)", cfg.Gateway.Bind)
	}
	if cfg.Gateway.Port == 1 {
		t.Errorf("port = %d — [client:] port LEAKED into gateway", cfg.Gateway.Port)
	}
	if cfg.Local.OllamaURL != "http://good:11434?x=1=y" {
		t.Errorf("ollama_url = %q — non-local sections LEAKED into local (reviewer was right)", cfg.Local.OllamaURL)
	}
	if cfg.Clients != nil && len(cfg.Clients) != 0 {
		t.Errorf("applyGatewayFile touched Clients: %+v", cfg.Clients)
	}
}
