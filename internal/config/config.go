// Package config handles loading and merging Tidegate configuration from
// multiple sources: embedded defaults, preset files, user config, and
// project-local .tidegate.conf files.
package config

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qo-roj/tidegate/internal/rules"
	"github.com/qo-roj/tidegate/internal/tabular"
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
	// VaultTTL is how long a redaction token stays resolvable.
	VaultTTL time.Duration
	// MetricsAddr is the listen address for /metrics and /stats.
	// Empty disables the metrics listener.
	MetricsAddr string
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

// Tabular holds the table-generalization policy ([tabular] section).
// Settings are only used when Mode is not "off"; the gateway defaults to
// "shadow" so the transform can be judged on real traffic before it rewrites
// anything.
type Tabular struct {
	Mode           string // off | shadow | apply
	MinRows        int
	SigFigs        int
	MaxCategorical int
	Text           string // hash (default) | auto | keep
	SaltFile       string
	Keep           []string
	Drop           []string
	Disable        []string
}

// AppConfig is the fully resolved configuration.
type AppConfig struct {
	Gateway Gateway
	Cloud   Cloud
	Local   Local
	Tabular Tabular
	Clients []Client // gateway-mode clients, in config order
	RuleSet *rules.RuleSet
}

// Options converts the config section into tabular options. The salt is not
// read here: the caller loads it once, because it touches the filesystem.
func (t Tabular) Options() tabular.Options {
	disable := make(map[string]bool, len(t.Disable))
	for _, name := range t.Disable {
		disable[strings.ToLower(strings.TrimSpace(name))] = true
	}
	return tabular.Options{
		MinRows:        t.MinRows,
		SigFigs:        t.SigFigs,
		MaxCategorical: t.MaxCategorical,
		Text:           t.Text,
		Keep:           t.Keep,
		Drop:           t.Drop,
		Disable:        disable,
	}
}

// ParsedMode is the tabular mode as a Mode value.
func (t Tabular) ParsedMode() tabular.Mode { return tabular.ParseMode(t.Mode) }

// knownGeneralizers are the names accepted in [tabular] disable.
var knownGeneralizers = map[string]bool{
	"email": true, "ip": true, "phone": true, "card": true, "ssn": true,
	"uuid": true, "url": true, "date": true, "number": true, "text": true,
}

// Validate checks the [tabular] section at load time. A bad pattern, an
// unknown generalizer name or a relative salt path must fail here rather than
// silently doing nothing at request time.
func (t Tabular) Validate() error {
	switch strings.ToLower(strings.TrimSpace(t.Mode)) {
	case "", "off", "shadow", "apply":
	default:
		return fmt.Errorf("tabular: unknown mode %q (want off, shadow or apply)", t.Mode)
	}
	switch t.Text {
	case "", "hash", "auto", "keep":
	default:
		return fmt.Errorf("tabular: unknown text policy %q (want hash, auto or keep)", t.Text)
	}
	for _, name := range t.Disable {
		if !knownGeneralizers[strings.ToLower(strings.TrimSpace(name))] {
			return fmt.Errorf("tabular: unknown generalizer %q in disable", name)
		}
	}
	if t.SaltFile != "" && !filepath.IsAbs(t.SaltFile) {
		return fmt.Errorf("tabular: salt_file must be an absolute path, got %q", t.SaltFile)
	}
	for _, p := range append(append([]string{}, t.Keep...), t.Drop...) {
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			return fmt.Errorf("tabular: invalid column pattern %q: %w", p, err)
		}
	}
	return nil
}

// ApplySafe refuses the configurations under which apply mode would forward
// raw cells: any text policy but hash leaves free text untouched, and a
// disabled generalizer leaves its whole column type untouched. Both are fine
// in shadow mode, where nothing is rewritten.
func (t Tabular) ApplySafe() error {
	if t.Text != "hash" {
		return fmt.Errorf("tabular: mode = apply requires text = hash (got %q); other text policies leave raw cells in blocks that skip pattern redaction", t.Text)
	}
	if len(t.Disable) > 0 {
		return fmt.Errorf("tabular: mode = apply does not support disable = %v; a disabled generalizer leaves that column type raw", t.Disable)
	}
	return nil
}

// expandUserPath resolves a leading ~ so a config copied from the docs does
// not create a literal "./~" directory relative to the service's CWD.
func expandUserPath(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// Load resolves configuration from all sources in order:
//  1. Built-in defaults (embedded in binary)
//  2. Preset (embedded in binary) — the preset indicated by user/project
//     config takes priority over the default desktop preset
//  3. User config (~/.config/tidegate/tidegate.conf)
//  4. Project-local config (./.tidegate.conf)
//  5. CLI flags (passed as params)
func Load(cliPort int, cliPreset string) (*AppConfig, error) {
	home, _ := os.UserHomeDir()
	cfg := &AppConfig{
		Gateway: Gateway{
			Port:        8842,
			Bind:        "127.0.0.1",
			LogLevel:    "info",
			Preset:      "desktop",
			VaultTTL:    24 * time.Hour,
			MetricsAddr: "127.0.0.1:9116",
		},
		Local: Local{
			OllamaURL:   "http://localhost:11434",
			OllamaModel: "llama3:8b",
		},
		Tabular: Tabular{
			Mode:           "shadow",
			MinRows:        3,
			SigFigs:        2,
			MaxCategorical: 200,
			Text:           "hash",
			SaltFile:       filepath.Join(home, ".config", "tidegate", "tabular.salt"),
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
	// Presets carry [gateway]/[local]/[tabular] settings as well as rules.
	// They are applied before user and project files so both can override.
	if presetData != nil {
		applyGatewayBytes(cfg, presetData)
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

	// [tabular] is validated at load time: a bad pattern, an unknown
	// generalizer or a relative salt path must fail here rather than
	// silently doing nothing per request.
	cfg.Tabular.SaltFile = expandUserPath(cfg.Tabular.SaltFile)
	if err := cfg.Tabular.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// applyGatewayFile reads [gateway] and [local] key/value settings from a config
// file and applies them to cfg. Later calls (project config) override earlier
// (user). Keys: bind, cert, key (paths), port, log_level; local: ollama_url,
// ollama_model.
//
// The rules parser skips these sections (they carry no rule data), so they are
// read from the raw file here. ollama_url matters in practice: the shipped
// `server` preset classifies /var/log/** as local-only, so a gateway whose
// Ollama URL points at a non-existent localhost:11434 BLOCKS all log analysis
// instead of summarising it.
func applyGatewayFile(cfg *AppConfig, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	applyGatewayBytes(cfg, data)
}

// applyGatewayBytes is applyGatewayFile for config bytes that are already in
// memory (embedded presets).
func applyGatewayBytes(cfg *AppConfig, data []byte) {
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
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
		if v == "" {
			// Empty values never override: a blank `ollama_url =` in a
			// later file must not wipe a valid earlier value (dual-model
			// review 2026-09-28; for gateway keys this also prevents an
			// accidental `bind =` from clearing to "" = all interfaces).
			continue
		}
		switch section {
		case "gateway":
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
			case "vault_ttl_hours":
				if h, err := strconv.Atoi(v); err == nil && h > 0 && h <= 8760 {
					cfg.Gateway.VaultTTL = time.Duration(h) * time.Hour
				}
			case "metrics_addr":
				cfg.Gateway.MetricsAddr = v
			}
		case "local":
			switch k {
			case "ollama_url":
				cfg.Local.OllamaURL = v
			case "ollama_model":
				cfg.Local.OllamaModel = v
			}
		case "tabular":
			switch k {
			case "mode":
				cfg.Tabular.Mode = strings.ToLower(v)
			case "min_rows":
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					cfg.Tabular.MinRows = n
				}
			case "sig_figs":
				if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 8 {
					cfg.Tabular.SigFigs = n
				}
			case "max_categorical":
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					cfg.Tabular.MaxCategorical = n
				}
			case "text":
				cfg.Tabular.Text = strings.ToLower(v)
			case "salt_file":
				cfg.Tabular.SaltFile = v
			case "keep":
				cfg.Tabular.Keep = splitCSVList(v)
			case "drop":
				cfg.Tabular.Drop = splitCSVList(v)
			case "disable":
				cfg.Tabular.Disable = splitCSVList(v)
			}
		}
	}
}

// splitCSVList parses a list-valued config entry. Bare comma-separated values
// are the canonical form; a TOML-style bracket array is also accepted because
// it is what people write in a .conf file that looks like TOML. The brackets
// are stripped ONLY when the value is a full list (starts '[' AND ends ']') —
// an unquoted regex that merely starts with a character class (`keep = [a-z]+_id`)
// must survive byte-exact; stripping its interior silently produced a pattern
// that compiled and matched nothing. Quote trimming likewise requires a
// matching pair — a stray quote is content, not punctuation.
func splitCSVList(v string) []string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '[' && v[len(v)-1] == ']' {
		v = v[1 : len(v)-1]
	}

	var out []string
	for _, part := range strings.Split(v, ",") {
		p := strings.TrimSpace(part)
		if len(p) >= 2 && (p[0] == '"' || p[0] == '\'') && p[len(p)-1] == p[0] {
			p = p[1 : len(p)-1]
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
