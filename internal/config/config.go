// Package config handles loading and merging Tidegate configuration from
// multiple sources: embedded defaults, preset files, user config, and
// project-local .tidegate.conf files.
package config

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/qo-roj/tidegate/internal/rules"
)

//go:embed rules/defaults.conf
var defaultsConf embed.FS

//go:embed rules/presets/desktop.conf
var desktopConf embed.FS

//go:embed rules/presets/server.conf
var serverConf embed.FS

//go:embed rules/presets/paranoid.conf
var paranoidConf embed.FS

//go:embed rules/presets/training-data.conf
var trainingDataConf embed.FS

// Gateway holds the runtime configuration for the Tidegate gateway.
type Gateway struct {
	Port     int
	Bind     string
	LogLevel string
	Preset   string
	// Gateway mode: when true, the proxy requires a valid client key on
	// every request. Enabled automatically when any client key is
	// configured (config file, --keyfile, or --require-key).
	RequireKey bool
	// TLS certificate and key (pem). Empty = plain HTTP.
	CertFile string
	KeyFile  string
}

// Client is one authorized gateway client (pre-shared key).
type Client struct {
	Name string
	Key  string
}

// Cloud holds cloud provider configuration.
type Cloud struct {
	AnthropicKey string
	OpenAIKey    string
	XAIKey       string
}

// Local holds local model (Ollama) configuration.
type Local struct {
	OllamaURL   string
	OllamaModel string
}

// AppConfig is the fully resolved configuration.
type AppConfig struct {
	Gateway Gateway
	Cloud   Cloud
	Local   Local
	Clients []Client // gateway-mode clients, in config order
	RuleSet *rules.RuleSet
}

// Load resolves configuration from all sources in order:
//  1. Built-in defaults (embedded in binary)
//  2. Preset (embedded in binary) — the preset indicated by user/project
//     config takes priority over the default desktop preset
//  3. User config (~/.config/tidegate/tidegate.conf)
//  4. Project-local config (./.tidegate.conf)
//  5. CLI flags (passed as params)
func Load(cliPort int, cliPreset string) (*AppConfig, error) {
	cfg := &AppConfig{
		Gateway: Gateway{
			Port:     8842,
			Bind:     "127.0.0.1",
			LogLevel: "info",
			Preset:   "desktop",
		},
		Local: Local{
			OllamaURL:   "http://localhost:11434",
			OllamaModel: "llama3:8b",
		},
	}

	// 1. Built-in defaults (embedded)
	defaultsData, err := defaultsConf.ReadFile("rules/defaults.conf")
	if err != nil {
		return nil, fmt.Errorf("reading embedded defaults: %w", err)
	}
	defaultsCfg, err := rules.ParseConfigBytes(defaultsData, "defaults")
	if err != nil {
		return nil, fmt.Errorf("parsing defaults: %w", err)
	}

	// Pass 1: read the preset selection from CLI, user config, and project
	// config (highest priority first). The preset choice determines which
	// preset layer is merged, so it must be known before any preset is loaded.
	presetChoice := ""
	if cliPreset != "" {
		presetChoice = cliPreset
	}
	home, _ := os.UserHomeDir()
	userConfigPath := filepath.Join(home, ".config", "tidegate", "tidegate.conf")
	var userCfg, projCfg *rules.Config
	if fileExists(userConfigPath) {
		userCfg, err = rules.ParseConfig(userConfigPath)
		if err != nil {
			return nil, fmt.Errorf("user config: %w", err)
		}
		if userCfg.Preset != "" && presetChoice == "" {
			presetChoice = userCfg.Preset
		}
	}
	if fileExists(".tidegate.conf") {
		projCfg, err = rules.ParseConfig(".tidegate.conf")
		if err != nil {
			return nil, fmt.Errorf("project config: %w", err)
		}
		if projCfg.Preset != "" && presetChoice == "" {
			presetChoice = projCfg.Preset
		}
	}
	if presetChoice != "" {
		cfg.Gateway.Preset = presetChoice
	}

	// 2. Preset (embedded) — resolved from pass 1
	presetData, err := loadPreset(cfg.Gateway.Preset)
	if err != nil {
		return nil, fmt.Errorf("loading preset %s: %w", cfg.Gateway.Preset, err)
	}

	// Build the ordered layer list: defaults → preset → user → project.
	// Layer stamps drive sticky-block semantics in BuildRuleSetLayered.
	layers := []rules.LayeredConfig{
		{Cfg: defaultsCfg, Layer: rules.LayerDefaults, Source: "defaults"},
	}
	if presetData != nil {
		presetCfg, err := rules.ParseConfigBytes(presetData, "preset:"+cfg.Gateway.Preset)
		if err != nil {
			return nil, fmt.Errorf("parsing preset: %w", err)
		}
		layers = append(layers, rules.LayeredConfig{Cfg: presetCfg, Layer: rules.LayerPreset, Source: "preset:" + cfg.Gateway.Preset})
	}
	if userCfg != nil {
		layers = append(layers, rules.LayeredConfig{Cfg: userCfg, Layer: rules.LayerUser, Source: "user"})
	}
	if projCfg != nil {
		layers = append(layers, rules.LayeredConfig{Cfg: projCfg, Layer: rules.LayerProject, Source: "project"})
	}

	// 5. CLI overrides
	if cliPort > 0 {
		cfg.Gateway.Port = cliPort
	}

	// [gateway] settings and [client:<name>] keys from user + project config.
	// The rules parser skips [gateway] sections (they carry no rule data),
	// so gateway key/values are read from the raw files here. Later files
	// (project) override earlier (user), matching preset-selection order.
	if userCfg != nil {
		applyGatewayFile(cfg, userConfigPath)
		for _, name := range sortedClientNames(userCfg) {
			cfg.Clients = append(cfg.Clients, Client{
				Name: name,
				Key:  userCfg.Clients[name].Key,
			})
		}
	}
	if projCfg != nil {
		applyGatewayFile(cfg, ".tidegate.conf")
		for _, name := range sortedClientNames(projCfg) {
			// Replace a same-named user-layer client (project wins).
			replaced := false
			for i := range cfg.Clients {
				if cfg.Clients[i].Name == name {
					cfg.Clients[i].Key = projCfg.Clients[name].Key
					replaced = true
					break
				}
			}
			if !replaced {
				cfg.Clients = append(cfg.Clients, Client{
					Name: name,
					Key:  projCfg.Clients[name].Key,
				})
			}
		}
	}

	// Gateway mode activates when any client key is configured.
	cfg.Gateway.RequireKey = len(cfg.Clients) > 0

	// Build the rule set with cross-layer block protection
	cfg.RuleSet = rules.BuildRuleSetLayered(layers)

	// Load cloud keys from environment
	cfg.Cloud.AnthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	cfg.Cloud.OpenAIKey = os.Getenv("OPENAI_API_KEY")
	cfg.Cloud.XAIKey = os.Getenv("XAI_API_KEY")

	return cfg, nil
}

// applyGatewayFile reads [gateway] key/value settings from a config file and
// applies them to cfg. Later calls (project config) override earlier (user).
// Keys: bind, cert, key (paths), port, log_level.
func applyGatewayFile(cfg *AppConfig, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	inGateway := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inGateway = strings.TrimSpace(line[1:len(line)-1]) == "gateway"
			continue
		}
		if !inGateway {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(stripHashComment(parts[1]))
		// Tolerate quoted values: bind = "0.0.0.0" must not carry the
		// quotes into net.Listen (review finding).
		v = strings.Trim(v, `"'`)
		switch k {
		case "bind":
			cfg.Gateway.Bind = v
		case "port":
			if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
				cfg.Gateway.Port = p
			}
		case "log_level":
			cfg.Gateway.LogLevel = v
		case "cert", "cert_file", "tls_cert":
			cfg.Gateway.CertFile = v
		case "key", "key_file", "tls_key":
			cfg.Gateway.KeyFile = v
		}
	}
}

// stripHashComment removes a trailing " #..." comment from a value.
func stripHashComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

// sortedClientNames returns the client names of a rules config in sorted
// order, so AppConfig.Clients is deterministic across runs.
func sortedClientNames(cfg *rules.Config) []string {
	names := make([]string, 0, len(cfg.Clients))
	for name := range cfg.Clients {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LoadKeyFile loads gateway client keys from a keyfile. Format:
//
//	name key
//	name2 key2
//
// Lines: whitespace-separated, comments (#) and blank lines ignored.
// Returns an error if any non-comment line lacks a name and key.
func LoadKeyFile(path string) ([]Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading keyfile: %w", err)
	}
	var clients []Client
	for _, raw := range strings.Split(string(data), "\n") {
		// Strip inline comments so "phone abc # old key" still parses
		// as two fields (review finding).
		if idx := strings.IndexAny(raw, "#;"); idx >= 0 {
			raw = raw[:idx]
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("keyfile line %q: want \"name key\"", line)
		}
		clients = append(clients, Client{Name: fields[0], Key: fields[1]})
	}
	return clients, nil
}

// loadPreset returns the embedded preset config data for the given preset name.
// Returns nil if the preset name is empty or unknown.
func loadPreset(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	switch name {
	case "":
		return nil, nil
	case "desktop":
		return desktopConf.ReadFile("rules/presets/desktop.conf")
	case "server":
		return serverConf.ReadFile("rules/presets/server.conf")
	case "paranoid":
		return paranoidConf.ReadFile("rules/presets/paranoid.conf")
	case "training-data":
		return trainingDataConf.ReadFile("rules/presets/training-data.conf")
	default:
		return nil, fmt.Errorf("unknown preset: %s", name)
	}
}

// fileExists returns true if the path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// SaveDefaultConfig writes a default config file to the given path.
func SaveDefaultConfig(path string) error {
	content := `# Tidegate Configuration
# Docs: https://github.com/qo-roj/tidegate/blob/main/docs/rules-guide.md

[gateway]
port = 8842
log_level = info

[cloud]
# Cloud providers — keys are read from env vars by default
# ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.

[local]
ollama_url = http://localhost:11434
ollama_model = llama3:8b

[redaction]
# All built-in patterns enabled by default

[preset]
desktop
`
	return os.WriteFile(path, []byte(content), 0644)
}

// ParsePort parses a port string and returns the integer, or the default if empty/invalid.
func ParsePort(s string, defaultPort int) int {
	if s == "" {
		return defaultPort
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return defaultPort
	}
	return port
}
