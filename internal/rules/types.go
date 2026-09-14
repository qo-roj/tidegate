// Package rules implements Tidegate's layered rule system for content
// classification. Rules determine what tier (public, redacted, local-only,
// blocked) applies to a given file path or content reference.
//
// Resolution order (later overrides earlier):
//  1. Built-in defaults (embedded in binary)
//  2. Preset rules (desktop, server, paranoid)
//  3. User config (~/.config/tidegate/tidegate.conf)
//  4. Project-local config (./.tidegate.conf)
//  5. CLI flags (highest priority)
package rules

// Tier represents the classification level for content.
type Tier int

const (
	// TierPublic: send to cloud as-is, no redaction.
	TierPublic Tier = iota
	// TierRedacted: scrub sensitive patterns, then send to cloud.
	TierRedacted
	// TierLocalOnly: route to local Ollama only, never to cloud.
	TierLocalOnly
	// TierBlocked: refuse access entirely, return error to agent.
	TierBlocked
)

func (t Tier) String() string {
	switch t {
	case TierPublic:
		return "public"
	case TierRedacted:
		return "redacted"
	case TierLocalOnly:
		return "local-only"
	case TierBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// PathRule maps a glob pattern to a tier.
type PathRule struct {
	Pattern string // glob pattern (doublestar-compatible)
	Tier    Tier
	Source  string // which config layer defined this rule (for debugging)
	Layer   int    // config layer that defined this rule (LayerDefaults..LayerProject)
}

// CmdRuleSpec is a parsed [cmd] rule before tier resolution.
type CmdRuleSpec struct {
	Pattern string // command glob (doublestar-compatible)
	Tier    string // "block", "local-only", "redact", or "public"
}

// Config layer ordering. Higher layers override lower ones; only
// human-authored layers (user, project) may downgrade a blocked tier.
const (
	LayerDefaults = 1 // embedded defaults.conf
	LayerPreset   = 2 // preset selected at load time
	LayerUser     = 3 // ~/.config/tidegate/tidegate.conf
	LayerProject  = 4 // ./.tidegate.conf
)

// LayeredConfig is one config layer fed into BuildRuleSetLayered.
type LayeredConfig struct {
	Cfg    *Config
	Layer  int
	Source string
}

// RuleSet holds all resolved rules and enabled redaction patterns.
type RuleSet struct {
	PathRules      []PathRule
	CmdRules       []PathRule      // command-string rules from [cmd] sections
	RedactionFlags map[string]bool // pattern name → enabled
	Preset         string
	AgentOverrides map[string]*RuleSet // per-agent rule overrides (by agent name)
}

// Client is a named gateway client with a pre-shared key (gateway mode).
type Client struct {
	Name string
	Key  string
}

// Config represents a parsed configuration file (one layer of the stack).
type Config struct {
	Blocks     []string           // paths to block
	LocalOnly  []string           // paths for local-only
	Redact     []string           // paths to redact
	Cmds       []CmdRuleSpec      // command rules from [cmd] sections
	Patterns   map[string]bool    // redaction pattern toggles
	AgentRules map[string]*Config // per-agent sections
	Clients    map[string]*Client // gateway-mode clients ([client:<name>] sections)
	Preset     string
}
