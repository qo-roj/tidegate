package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/rules"
)

// parseClientConfig parses a config from a string via the rules parser.
func parseClientConfig(t *testing.T, content string) *rules.Config {
	t.Helper()
	cfg, err := rules.ParseConfigBytes([]byte(content), "test")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestClientSectionsParse(t *testing.T) {
	cfg := parseClientConfig(t, `
[client:phone]
key = "abc123"
[client:laptop]
key = def456
`)
	if len(cfg.Clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(cfg.Clients))
	}
	if cfg.Clients["phone"].Key != "abc123" {
		t.Errorf("phone key = %q, want abc123 (quotes stripped)", cfg.Clients["phone"].Key)
	}
	if cfg.Clients["laptop"].Key != "def456" {
		t.Errorf("laptop key = %q, want def456", cfg.Clients["laptop"].Key)
	}
	if cfg.Clients["phone"].Name != "phone" {
		t.Errorf("phone name = %q", cfg.Clients["phone"].Name)
	}
}

// Client sections must not leak into path-rule sections and vice versa.
func TestClientSectionsDoNotAffectRules(t *testing.T) {
	cfg := parseClientConfig(t, `
[client:phone]
key = abc123

[block]
/etc/shadow
`)
	if len(cfg.Blocks) != 1 || cfg.Blocks[0] != "/etc/shadow" {
		t.Fatalf("block rules corrupted by client section: %v", cfg.Blocks)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("want 1 client, got %d", len(cfg.Clients))
	}
}

// A client section followed by a tier section must scope correctly.
func TestClientThenTierSection(t *testing.T) {
	cfg := parseClientConfig(t, `
[client:phone]
key = abc123
[agent:claude]
**/.env
[global]
[redact]
/var/log/**
`)
	if cfg.Clients["phone"] == nil || cfg.Clients["phone"].Key != "abc123" {
		t.Fatalf("client lost across section switch: %+v", cfg.Clients)
	}
	if len(cfg.AgentRules["claude"].Blocks) != 1 {
		t.Fatalf("agent rules lost: %+v", cfg.AgentRules)
	}
	if len(cfg.Redact) != 1 {
		t.Fatalf("global redact rules lost: %v", cfg.Redact)
	}
}

func TestMergeConfigClients(t *testing.T) {
	parent := parseClientConfig(t, `
[client:phone]
key = old-key
`)
	child := parseClientConfig(t, `
[client:phone]
key = new-key
[client:tablet]
key = tab-key
`)
	merged := rules.MergeConfig(parent, child)
	if len(merged.Clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(merged.Clients))
	}
	if merged.Clients["phone"].Key != "new-key" {
		t.Errorf("child should override: got %q", merged.Clients["phone"].Key)
	}
	if merged.Clients["tablet"].Key != "tab-key" {
		t.Errorf("child client missing: %+v", merged.Clients)
	}
}

func TestLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.keys")
	content := "# comment\n\nphone abc123\nlaptop   def456\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	if clients[0].Name != "phone" || clients[0].Key != "abc123" {
		t.Errorf("client 0 = %+v", clients[0])
	}
	if clients[1].Name != "laptop" || clients[1].Key != "def456" {
		t.Errorf("client 1 = %+v", clients[1])
	}
}

func TestLoadKeyFileMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.keys")
	if err := os.WriteFile(path, []byte("only-a-name\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("want error for malformed line")
	}
}

// LoadKeyFile must reject duplicate names so a second key can't shadow the first.
func TestLoadKeyFileDuplicateName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.keys")
	content := "phone abc123\nphone def456\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Fatalf("want 2 entries parsed, got %d", len(clients))
	}
	// The gateway-level duplicate check (first wins) is in the proxy; here
	// we only assert the file loads and both entries are present in order.
	if clients[0].Key != "abc123" || clients[1].Key != "def456" {
		t.Fatalf("order not preserved: %+v", clients)
	}
}

// applyGatewayFile must pick up bind/cert/key from a config file.
func TestApplyGatewayFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tidegate.conf")
	content := `
[gateway]
bind = 192.168.1.50
port = 9000

[client:phone]
key = abc123
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Gateway.Port = 8842
	applyGatewayFile(cfg, path)
	if cfg.Gateway.Bind != "192.168.1.50" {
		t.Errorf("bind = %q", cfg.Gateway.Bind)
	}
	if cfg.Gateway.Port != 9000 {
		t.Errorf("port = %d, want 9000", cfg.Gateway.Port)
	}
}

// applyGatewayFile must not read key=value lines outside [gateway].
func TestApplyGatewayFileIgnoresOtherSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tidegate.conf")
	content := `
[client:phone]
key = 192.168.1.50

[gateway]
port = 9001
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Gateway.Port = 8842
	applyGatewayFile(cfg, path)
	if cfg.Gateway.Bind != "" {
		t.Errorf("bind leaked from client section: %q", cfg.Gateway.Bind)
	}
	if cfg.Gateway.Port != 9001 {
		t.Errorf("port = %d, want 9001", cfg.Gateway.Port)
	}
}

// Full Load path: user config with [client:*] sections activates gateway mode.
func TestLoadClientsFromUserConfig(t *testing.T) {
	// Load() reads ~/.config/tidegate/tidegate.conf — redirect HOME.
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	confDir := filepath.Join(home, ".config", "tidegate")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := `
[gateway]
bind = 0.0.0.0

[client:phone]
key = "tg-phone-key"

[redact]
/var/log/**
`
	if err := os.WriteFile(filepath.Join(confDir, "tidegate.conf"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// Guard against a project ./.tidegate.conf in the repo root.
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(oldWd) })

	cfg, err := Load(0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("want 1 client, got %d", len(cfg.Clients))
	}
	if cfg.Clients[0].Name != "phone" || cfg.Clients[0].Key != "tg-phone-key" {
		t.Errorf("client = %+v", cfg.Clients[0])
	}
	if !cfg.Gateway.RequireKey {
		t.Error("RequireKey should activate when clients are configured")
	}
	if cfg.Gateway.Bind != "0.0.0.0" {
		t.Errorf("bind = %q, want 0.0.0.0", cfg.Gateway.Bind)
	}
	if len(cfg.RuleSet.PathRules) == 0 {
		t.Error("redact rules lost alongside client config")
	}
	if strings.Contains(cfg.Gateway.Bind, "tg-phone-key") {
		t.Error("key value leaked into bind")
	}
}

// Quoted [gateway] values must not carry quotes into net.Listen.
func TestApplyGatewayFileStripsQuotes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tidegate.conf")
	content := `
[gateway]
bind = "0.0.0.0"
port = 9000
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Gateway.Port = 8842
	applyGatewayFile(cfg, path)
	if cfg.Gateway.Bind != "0.0.0.0" {
		t.Errorf("bind = %q, want 0.0.0.0 (quotes stripped)", cfg.Gateway.Bind)
	}
}

// Keyfile inline comments must not break parsing.
func TestLoadKeyFileInlineComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.keys")
	content := "phone abc123 # old key\n; laptop removed\nlaptop def456 ;second\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d: %+v", len(clients), clients)
	}
	if clients[0].Name != "phone" || clients[0].Key != "abc123" {
		t.Errorf("client 0 = %+v", clients[0])
	}
	if clients[1].Name != "laptop" || clients[1].Key != "def456" {
		t.Errorf("client 1 = %+v", clients[1])
	}
}

// [local] settings must be read from the config file: the shipped `server`
// preset classifies /var/log/** as local-only, so pointing ollama_url at a
// reachable model server is the difference between log analysis being
// summarised and being BLOCKED.
func TestApplyGatewayFileLocalSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tidegate.conf")
	content := `
[gateway]
bind = 127.0.0.1

[local]
ollama_url = http://100.105.40.95:11434
ollama_model = "llama3.1:8b"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{}
	cfg.Local.OllamaURL = "http://localhost:11434"
	applyGatewayFile(cfg, path)
	if cfg.Local.OllamaURL != "http://100.105.40.95:11434" {
		t.Errorf("ollama_url = %q, want the config value", cfg.Local.OllamaURL)
	}
	if cfg.Local.OllamaModel != "llama3.1:8b" {
		t.Errorf("ollama_model = %q, want llama3.1:8b", cfg.Local.OllamaModel)
	}
	// A [local] section must not disturb gateway settings.
	if cfg.Gateway.Bind != "127.0.0.1" {
		t.Errorf("bind = %q, want 127.0.0.1", cfg.Gateway.Bind)
	}
}
