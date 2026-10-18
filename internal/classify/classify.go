// Package classify implements content-block-level classification for the
// Tidegate gateway. It parses LLM API request structures, extracts content
// blocks (messages, tool results, file contents), and assigns a tier to each
// block using path rules, command rules, and pattern-based heuristics.
//
// When a block contains multiple sub-tier elements, it is escalated to the
// highest tier present (conservative: when in doubt, escalate).
package classify

import (
	"encoding/json"
	"strings"

	"github.com/qo-roj/tidegate/internal/rules"
)

// ContentBlock represents a unit of content within an LLM API request.
// Blocks are extracted from messages, tool results, and file references.
type ContentBlock struct {
	Content       string // the text content
	FilePath      string // if this block is from a file read, the path
	Command       string // if this block is from a command execution, the command
	IsToolResult  bool   // true if this block is a tool-use result
	IsSystemBlock bool   // true for system messages (usually public)
	Role          string // message role: system, user, assistant, tool
}

// ClassificationResult holds the tier and reasoning for a single block.
type ClassificationResult struct {
	Tier   rules.Tier
	Source string // which rule matched
	Block  ContentBlock
	Reason string
}

// Classifier classifies content blocks using path rules, command rules,
// and pattern-based heuristics.
type Classifier struct {
	ruleSet *rules.RuleSet
}

// New creates a Classifier from a RuleSet.
func New(rs *rules.RuleSet) *Classifier {
	return &Classifier{ruleSet: rs}
}

// ClassifyBlock determines the tier for a single content block.
// The agent parameter enables per-agent rule overrides (agent-specific
// [agent:<name>] sections in config). Pass "" to use global rules only.
// Classification order (first match wins, most specific first):
//  1. Command rules (if block is a tool result with a command)
//  2. Path rules (if block contains a file path) — with agent overrides
//  3. Pattern-based classification (scan content for sensitive patterns)
func (c *Classifier) ClassifyBlock(block ContentBlock, agent string) ClassificationResult {
	// 1. Command rules — if this is a tool result with a command.
	// Configured [cmd] rules take precedence; the built-in deny-list runs
	// as a fail-safe floor when no configured rule matches (or when command
	// rules were never configured at all).
	if block.IsToolResult && block.Command != "" {
		if c.ruleSet != nil {
			tier, source := c.ruleSet.ClassifyCommand(block.Command)
			if tier != rules.TierPublic || source != "default" {
				return ClassificationResult{
					Tier:   tier,
					Source: source,
					Block:  block,
					Reason: "matched command rule: " + block.Command,
				}
			}
		}
		tier, source := c.classifyCommand(block.Command)
		if tier != rules.TierPublic || source != "default" {
			return ClassificationResult{
				Tier:   tier,
				Source: source,
				Block:  block,
				Reason: "matched command rule: " + block.Command,
			}
		}
	}

	// 2. Path rules — if block references a file path
	// Use ClassifyPathForAgent so per-agent overrides take precedence
	if block.FilePath != "" {
		tier, source := c.ruleSet.ClassifyPathForAgent(block.FilePath, agent)
		if tier != rules.TierPublic || source != "default" {
			return ClassificationResult{
				Tier:   tier,
				Source: source,
				Block:  block,
				Reason: "matched path rule: " + block.FilePath,
			}
		}
	}

	// 3. Pattern-based — scan content for file paths and classify them
	tier := c.classifyByContent(block.Content, agent)
	if tier != rules.TierPublic {
		return ClassificationResult{
			Tier:   tier,
			Source: "pattern",
			Block:  block,
			Reason: "content contains sensitive patterns or paths",
		}
	}

	return ClassificationResult{
		Tier:   rules.TierPublic,
		Source: "default",
		Block:  block,
		Reason: "no rules matched",
	}
}

// classifyCommand matches a command string against command rules.
// Until proper [cmd] section parsing is implemented, uses a deny-list
// of dangerous commands as a fail-safe. Commands matching the deny-list
// are escalated to TierLocalOnly; everything else defaults to Public.
func (c *Classifier) classifyCommand(cmd string) (rules.Tier, string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return rules.TierPublic, "default"
	}

	// Fail-safe deny-list: commands that read sensitive system files.
	// These should never be sent to the cloud unredacted.
	dangerousCmds := []string{
		"cat /etc/shadow", "cat /etc/passwd",
		"cat ~/.ssh", "cat /root/.ssh",
		"cat .env",
		"sudo cat", "sudo -a cat",
	}
	lowerCmd := strings.ToLower(cmd)
	for _, dangerous := range dangerousCmds {
		if strings.Contains(lowerCmd, strings.ToLower(dangerous)) {
			return rules.TierLocalOnly, "cmd-denylist"
		}
	}
	// Any .env read anywhere (covers subdirectories — the old literal
	// "cat */.env" entry never matched anything).
	if strings.Contains(lowerCmd, ".env") {
		return rules.TierLocalOnly, "cmd-denylist"
	}

	// Commands that read log files should be redacted
	logCmds := []string{"journalctl", "dmesg", "cat /var/log", "tail /var/log", "less /var/log"}
	for _, logCmd := range logCmds {
		if strings.Contains(lowerCmd, logCmd) {
			return rules.TierRedacted, "cmd-denylist"
		}
	}

	return rules.TierPublic, "default"
}

// classifyByContent scans content for file paths and sensitive patterns.
// If a file path is found that matches a path rule, the tier is escalated.
// The agent parameter enables per-agent path overrides.
func (c *Classifier) classifyByContent(content string, agent string) rules.Tier {
	highestTier := rules.TierPublic

	// Extract potential file paths from content
	paths := extractPaths(content)
	for _, path := range paths {
		tier, _ := c.ruleSet.ClassifyPathForAgent(path, agent)
		if tier > highestTier {
			highestTier = tier
		}
		if highestTier == rules.TierBlocked {
			break
		}
	}

	return highestTier
}

// extractPaths finds potential file paths in content.
// Scans all words for path-like patterns: /abs/path, ~/path, ~user/path.
func extractPaths(content string) []string {
	var paths []string
	seen := make(map[string]bool)

	words := strings.Fields(content)
	for _, word := range words {
		word = strings.TrimRight(word, ":;,.!?\"'()[]{}")
		if len(word) < 2 {
			continue
		}
		// Absolute paths, ~/paths, and ~user/ paths
		// Avoid matching bare ~ or ~~ (no slash after tilde)
		if strings.HasPrefix(word, "/") ||
			strings.HasPrefix(word, "~/") ||
			(strings.HasPrefix(word, "~") && len(word) > 1 && word[1] != '~' && strings.Contains(word, "/")) {
			if !seen[word] {
				paths = append(paths, word)
				seen[word] = true
			}
		}
	}

	return paths
}

// ParseRequest parses an LLM API request body and extracts content blocks.
// Supports both OpenAI and Anthropic message formats.
func ParseRequest(body []byte) []ContentBlock {
	_, blocks, _ := ParseRequestAligned(body)
	return blocks
}

// ParseRequestAligned parses a request into message objects and one content
// block per message, index-aligned. Messages that are not JSON objects are
// omitted from both slices, so blocks[i] always describes messages[i].
func ParseRequestAligned(body []byte) ([]map[string]interface{}, []ContentBlock, bool) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, false
	}

	messages, ok := raw["messages"].([]interface{})
	if !ok {
		return nil, nil, false
	}

	msgs := make([]map[string]interface{}, 0, len(messages))
	blocks := make([]ContentBlock, 0, len(messages))
	for _, msg := range messages {
		m, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}

		role, _ := m["role"].(string)
		content := extractContent(m)

		block := ContentBlock{
			Content:       content,
			Role:          role,
			IsSystemBlock: role == "system",
		}

		// Check if this is a tool result
		if role == "tool" || role == "assistant" {
			if _, hasToolCall := m["tool_calls"]; hasToolCall {
				block.IsToolResult = true
			}
			if toolCallID, ok := m["tool_call_id"].(string); ok && toolCallID != "" {
				block.IsToolResult = true
			}
		}

		// Try to extract file path from content
		block.FilePath = extractFilePathFromContent(content)
		// Try to extract command from content
		block.Command = extractCommandFromContent(content)

		msgs = append(msgs, m)
		blocks = append(blocks, block)
	}

	return msgs, blocks, true
}

// extractContent gets the text content from a message, handling both
// string content and array content (Anthropic format).
func extractContent(m map[string]interface{}) string {
	// String content (OpenAI format)
	if content, ok := m["content"].(string); ok {
		return content
	}

	// Array content (Anthropic format)
	if content, ok := m["content"].([]interface{}); ok {
		var sb strings.Builder
		for _, part := range content {
			if p, ok := part.(map[string]interface{}); ok {
				if text, ok := p["text"].(string); ok {
					sb.WriteString(text)
					sb.WriteString("\n")
				}
				if text, ok := p["content"].(string); ok {
					sb.WriteString(text)
					sb.WriteString("\n")
				}
			}
		}
		return sb.String()
	}

	return ""
}

// extractFilePathFromContent tries to find a file path in content like
// "Here's my nginx config:\n<file content>" or tool results with file paths.
func extractFilePathFromContent(content string) string {
	// Common patterns: "read file /etc/nginx/nginx.conf", "cat /path/to/file"
	// For now, look for paths in common tool-result formats
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "path:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// extractCommandFromContent tries to find a command in tool-result content.
func extractCommandFromContent(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "command:") || strings.HasPrefix(lower, "cmd:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// EscalateTier returns the higher of two tiers (for mixed-tier blocks).
func EscalateTier(a, b rules.Tier) rules.Tier {
	if a > b {
		return a
	}
	return b
}
