package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedRulesMatchSourceTree guards a real trap: the embedded copies
// under internal/config/rules are what the binary actually ships, while
// rules/ at the repo root is what the docs and contributors edit. They are
// duplicated only because go:embed cannot reference a parent directory.
// Editing the root copies alone silently changes nothing at runtime.
func TestEmbeddedRulesMatchSourceTree(t *testing.T) {
	for _, name := range []string{
		"defaults.conf",
		filepath.Join("presets", "desktop.conf"),
		filepath.Join("presets", "server.conf"),
		filepath.Join("presets", "paranoid.conf"),
		filepath.Join("presets", "training-data.conf"),
	} {
		embedded, err := os.ReadFile(filepath.Join("rules", name))
		if err != nil {
			t.Fatalf("reading embedded %s: %v", name, err)
		}
		source, err := os.ReadFile(filepath.Join("..", "..", "rules", name))
		if err != nil {
			t.Fatalf("reading source %s: %v", name, err)
		}
		if !bytes.Equal(embedded, source) {
			t.Errorf("%s is out of sync with the repo-root rules/ copy; "+
				"run: cp rules/%s internal/config/rules/%s", name, name, name)
		}
	}
}
