package wrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeFreshConfig(t *testing.T) {
	home := t.TempDir()
	res, err := Apply("claude", "http://127.0.0.1:8842/anthropic/v1", "", home)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Changed {
		t.Fatalf("result = %+v", res)
	}

	var root map[string]interface{}
	data, err := os.ReadFile(claudePath(home))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	env := root["env"].(map[string]interface{})
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8842/anthropic/v1" {
		t.Fatalf("env = %v", env)
	}

	if _, err := Remove("claude", home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(claudePath(home)); !os.IsNotExist(err) {
		t.Fatalf("created file should be removed, stat err = %v", err)
	}
}

func TestClaudePreservesExistingSettings(t *testing.T) {
	home := t.TempDir()
	path := claudePath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	original := `{
  "theme": "dark",
  "env": {
    "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
    "OTHER": "keep"
  }
}
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply("claude", "http://127.0.0.1:8842/anthropic/v1", "gw-key", home); err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &root)
	env := root["env"].(map[string]interface{})
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8842/anthropic/v1" || env["ANTHROPIC_AUTH_TOKEN"] != "gw-key" {
		t.Fatalf("env after wrap = %v", env)
	}

	if _, err := Remove("claude", home); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	json.Unmarshal(data, &root)
	env = root["env"].(map[string]interface{})
	if env["ANTHROPIC_BASE_URL"] != "https://api.anthropic.com" || env["OTHER"] != "keep" {
		t.Fatalf("env after unwrap = %v", env)
	}
	if _, exists := env["ANTHROPIC_AUTH_TOKEN"]; exists {
		t.Fatal("token key should have been removed")
	}
	if root["theme"] != "dark" {
		t.Fatalf("unrelated setting lost: %v", root)
	}
}

func TestOpenCode(t *testing.T) {
	home := t.TempDir()
	if _, err := Apply("opencode", "http://127.0.0.1:8842/openai/v1", "", home); err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	data, _ := os.ReadFile(openCodePath(home))
	json.Unmarshal(data, &root)
	provider := root["provider"].(map[string]interface{})["tidegate"].(map[string]interface{})
	opts := provider["options"].(map[string]interface{})
	if opts["baseURL"] != "http://127.0.0.1:8842/openai/v1" {
		t.Fatalf("provider = %v", provider)
	}

	if _, err := Remove("opencode", home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(openCodePath(home)); !os.IsNotExist(err) {
		t.Fatal("created opencode config should be removed")
	}
}

func TestCodexRoundTrip(t *testing.T) {
	home := t.TempDir()
	path := codexPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	original := "model = \"gpt-5-codex\"\n\n[profiles.fast]\nmodel = \"gpt-5\"\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply("codex", "http://127.0.0.1:8842/openai/v1", "", home); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "[model_providers.tidegate]") {
		t.Fatalf("provider block missing:\n%s", data)
	}
	if !strings.HasPrefix(string(data), codexHeader) {
		t.Fatalf("header block must come first:\n%s", data)
	}

	if _, err := Remove("codex", home); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != original {
		t.Fatalf("unwrap mismatch:\n got %q\nwant %q", data, original)
	}
}

func TestCodexRejectsExistingProvider(t *testing.T) {
	home := t.TempDir()
	path := codexPath(home)
	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, []byte("model_provider = \"anthropic\"\n"), 0644)

	if _, err := Apply("codex", "http://x", "", home); err == nil {
		t.Fatal("expected refusal when model_provider is already set")
	}
}

func TestCodexWithKey(t *testing.T) {
	home := t.TempDir()
	if _, err := Apply("codex", "http://127.0.0.1:8842/openai/v1", "gw-key", home); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(codexPath(home))
	if !strings.Contains(string(data), `http_headers = { "X-Tidegate-Key" = "gw-key" }`) {
		t.Fatalf("gateway key not in provider block:\n%s", data)
	}
	info, _ := os.Stat(codexPath(home))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config with key should be 0600, got %v", info.Mode().Perm())
	}
}

func TestEnvTarget(t *testing.T) {
	res, err := Apply("env", "http://127.0.0.1:8842/openai/v1", "k", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("env target should not touch files")
	}
	joined := strings.Join(res.Exports, "\n")
	if !strings.Contains(joined, "OPENAI_BASE_URL=http://127.0.0.1:8842/openai/v1") ||
		!strings.Contains(joined, "OPENAI_API_KEY=k") {
		t.Fatalf("exports = %v", res.Exports)
	}
}

func TestUnknownAgent(t *testing.T) {
	if _, err := Apply("nonexistent", "http://x", "", t.TempDir()); err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestUnwrapWithoutWrap(t *testing.T) {
	if _, err := Remove("claude", t.TempDir()); err == nil {
		t.Fatal("expected error when no wrap state exists")
	}
}

func TestDefaultBaseURL(t *testing.T) {
	if got := DefaultBaseURL("claude", 8842); got != "http://127.0.0.1:8842/anthropic" {
		t.Fatalf("claude base = %q", got)
	}
	if got := DefaultBaseURL("codex", 8842); got != "http://127.0.0.1:8842/openai/v1" {
		t.Fatalf("codex base = %q", got)
	}
	if got := DefaultBaseURL("opencode", 9000); got != "http://127.0.0.1:9000/openai/v1" {
		t.Fatalf("opencode base = %q", got)
	}
}

func TestCodexPreservesMode(t *testing.T) {
	home := t.TempDir()
	path := codexPath(home)
	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, []byte("model = \"gpt-5-codex\"\n"), 0600)

	if _, err := Apply("codex", "http://127.0.0.1:8842/openai/v1", "", home); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove("codex", home); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestCodexRejectsDuplicateProviderTable(t *testing.T) {
	home := t.TempDir()
	path := codexPath(home)
	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, []byte("[model_providers.tidegate]\nname = \"x\"\n"), 0644)

	if _, err := Apply("codex", "http://127.0.0.1:8842/openai/v1", "", home); err == nil {
		t.Fatal("expected refusal when the provider table already exists")
	}
}

// TestCodexRootKeysNotSwallowed is Sid's Q3 case: a standard Codex config
// starts with root keys, so the provider table must go to EOF — a table
// header at the top would absorb every root key that follows it.
func TestCodexRootKeysNotSwallowed(t *testing.T) {
	home := t.TempDir()
	path := codexPath(home)
	os.MkdirAll(filepath.Dir(path), 0755)
	original := "model = \"gpt-5-codex\"\napproval_policy = \"on-request\"\n\n[profiles.fast]\nmodel = \"gpt-5\"\n"
	os.WriteFile(path, []byte(original), 0644)

	if _, err := Apply("codex", "http://127.0.0.1:8842/openai/v1", "", home); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	modelIdx := strings.Index(text, `model = "gpt-5-codex"`)
	tableIdx := strings.Index(text, "[model_providers.tidegate]")
	if modelIdx < 0 || tableIdx < 0 {
		t.Fatalf("missing pieces:\n%s", text)
	}
	if modelIdx > tableIdx {
		t.Fatalf("root key fell under the provider table:\n%s", text)
	}
	if !strings.HasSuffix(text, "# <<< tidegate provider <<<\n") {
		t.Fatalf("provider table must be last:\n%s", text)
	}

	if _, err := Remove("codex", home); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != original {
		t.Fatalf("round-trip mismatch:\n got %q\nwant %q", data, original)
	}
}
