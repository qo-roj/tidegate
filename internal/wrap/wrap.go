// Package wrap configures agent CLIs to route through Tidegate, and undoes it.
//
// Copying a base_url by hand is the main adoption friction for a local
// gateway. wrap edits the agent's own config in place, records exactly what
// it changed, and unwrap puts it back — including deleting a file it created.
package wrap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProviderFor maps an agent to the upstream path prefix it should use.
func ProviderFor(agent string) string {
	switch agent {
	case "claude":
		return "anthropic"
	default:
		return "openai"
	}
}

// DefaultBaseURL builds the gateway URL an agent should point at. The
// Anthropic SDK appends /v1/messages itself, so claude gets no /v1 suffix;
// OpenAI-compatible clients expect base_url to already end in /v1.
func DefaultBaseURL(agent string, port int) string {
	if port == 0 {
		port = 8842
	}
	if agent == "claude" {
		return fmt.Sprintf("http://127.0.0.1:%d/anthropic", port)
	}
	return fmt.Sprintf("http://127.0.0.1:%d/%s/v1", port, ProviderFor(agent))
}

// Result describes what happened to the agent's config.
type Result struct {
	Agent      string
	ConfigPath string
	// Changed is false for agents that need no file (env).
	Changed bool
	// Created is true when wrap created the config file.
	Created bool
	// Exports holds shell exports for the env target.
	Exports []string
}

type keyState struct {
	Path []string    `json:"path"`
	Prev interface{} `json:"prev,omitempty"`
	Had  bool        `json:"had"`
}

type entry struct {
	Agent      string              `json:"agent"`
	ConfigPath string              `json:"config_path"`
	Created    bool                `json:"created"`
	Mode       uint32              `json:"mode,omitempty"`
	Backup     string              `json:"backup,omitempty"`
	Keys       map[string]keyState `json:"keys,omitempty"`
}

type state struct {
	Entries map[string]entry `json:"entries"`
}

// Agents lists the supported targets.
func Agents() []string {
	return []string{"claude", "codex", "opencode", "env"}
}

// Apply configures agent to use baseURL. key is optional (gateway mode).
func Apply(agent, baseURL, key, home string) (Result, error) {
	switch agent {
	case "env":
		return exportResult(agent, baseURL, key), nil
	case "claude":
		return applyJSON(agent, claudePath(home), baseURL, key, []string{"env", "ANTHROPIC_BASE_URL"}, []string{"env", "ANTHROPIC_AUTH_TOKEN"}, home)
	case "opencode":
		return applyOpenCode(baseURL, key, home)
	case "codex":
		return applyCodex(baseURL, key, home)
	default:
		return Result{}, fmt.Errorf("unknown agent %q (supported: %s)", agent, strings.Join(Agents(), ", "))
	}
}

// Remove restores the agent's configuration.
func Remove(agent, home string) (Result, error) {
	switch agent {
	case "env":
		return Result{Agent: agent}, nil
	case "claude":
		return removeJSON(agent, claudePath(home), home)
	case "opencode":
		return removeJSON(agent, openCodePath(home), home)
	case "codex":
		return removeCodex(home)
	default:
		return Result{}, fmt.Errorf("unknown agent %q (supported: %s)", agent, strings.Join(Agents(), ", "))
	}
}

func exportResult(agent, baseURL, key string) Result {
	env := []string{
		"export ANTHROPIC_BASE_URL=" + baseURL,
		"export OPENAI_BASE_URL=" + baseURL,
	}
	if key != "" {
		env = append(env, "export ANTHROPIC_AUTH_TOKEN="+key, "export OPENAI_API_KEY="+key)
	}
	return Result{Agent: agent, Exports: env}
}

func claudePath(home string) string { return filepath.Join(home, ".claude", "settings.json") }
func openCodePath(home string) string {
	return filepath.Join(home, ".config", "opencode", "opencode.json")
}
func codexPath(home string) string { return filepath.Join(home, ".codex", "config.toml") }

func statePath(home string) string {
	return filepath.Join(home, ".config", "tidegate", "wrap.json")
}

func loadState(home string) state {
	s := state{Entries: map[string]entry{}}
	data, err := os.ReadFile(statePath(home))
	if err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.Entries == nil {
		s.Entries = map[string]entry{}
	}
	return s
}

func saveState(home string, s state) error {
	path := statePath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func readJSONObject(path string) (map[string]interface{}, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]interface{}{}, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]interface{}{}, false, nil
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, false, fmt.Errorf("parsing %s: %w", path, err)
	}
	return root, false, nil
}

func writeJSONObject(path string, root map[string]interface{}, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), mode)
}

// lookup walks a nested JSON path.
func lookup(root map[string]interface{}, path []string) (interface{}, bool) {
	var cur interface{} = root
	for _, seg := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath sets a nested value, creating intermediate objects.
func setPath(root map[string]interface{}, path []string, val interface{}) {
	cur := root
	for _, seg := range path[:len(path)-1] {
		next, ok := cur[seg].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			cur[seg] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = val
}

// deletePath removes a nested value and prunes empty objects.
func deletePath(root map[string]interface{}, path []string) {
	parent := root
	for _, seg := range path[:len(path)-1] {
		next, ok := parent[seg].(map[string]interface{})
		if !ok {
			return
		}
		parent = next
	}
	delete(parent, path[len(path)-1])

	// Prune empty ancestors bottom-up.
	for i := len(path) - 1; i >= 1; i-- {
		p := root
		ok := true
		for _, seg := range path[:i-1] {
			m, isMap := p[seg].(map[string]interface{})
			if !isMap {
				ok = false
				break
			}
			p = m
		}
		if !ok {
			return
		}
		child, isMap := p[path[i-1]].(map[string]interface{})
		if !isMap || len(child) > 0 {
			return
		}
		delete(p, path[i-1])
	}
}

// applyJSON writes nested keys into a JSON config, recording prior values.
func applyJSON(agent, path, baseURL, key string, basePath, keyPath []string, home string) (Result, error) {
	root, created, err := readJSONObject(path)
	if err != nil {
		return Result{}, err
	}

	s := loadState(home)
	e := entry{Agent: agent, ConfigPath: path, Created: created, Keys: map[string]keyState{}}
	if info, err := os.Stat(path); err == nil {
		e.Mode = uint32(info.Mode().Perm())
	}

	set := func(p []string, v interface{}) {
		prev, had := lookup(root, p)
		e.Keys[strings.Join(p, ".")] = keyState{Path: p, Prev: prev, Had: had}
		setPath(root, p, v)
	}
	set(basePath, baseURL)
	if key != "" {
		set(keyPath, key)
	}

	mode := os.FileMode(0644)
	if key != "" {
		mode = 0600
	}
	if err := writeJSONObject(path, root, mode); err != nil {
		return Result{}, err
	}
	s.Entries[agent] = e
	if err := saveState(home, s); err != nil {
		return Result{}, err
	}
	return Result{Agent: agent, ConfigPath: path, Changed: true, Created: created}, nil
}

// removeJSON restores recorded prior values.
func removeJSON(agent, path, home string) (Result, error) {
	s := loadState(home)
	e, ok := s.Entries[agent]
	if !ok {
		return Result{Agent: agent, ConfigPath: path}, fmt.Errorf("no wrap state for %s (was it wrapped?)", agent)
	}

	root, _, err := readJSONObject(path)
	if err != nil {
		return Result{}, err
	}
	// Restore in reverse depth order so pruning does not remove a parent
	// before a sibling key is restored.
	keys := make([]keyState, 0, len(e.Keys))
	for _, k := range e.Keys {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i].Path) > len(keys[j].Path) })
	for _, k := range keys {
		if k.Had {
			setPath(root, k.Path, k.Prev)
		} else {
			deletePath(root, k.Path)
		}
	}

	if e.Created && len(root) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return Result{}, err
		}
	} else {
		mode := os.FileMode(0644)
		if e.Mode != 0 {
			mode = os.FileMode(e.Mode)
		}
		if err := writeJSONObject(path, root, mode); err != nil {
			return Result{}, err
		}
	}

	delete(s.Entries, agent)
	if err := saveState(home, s); err != nil {
		return Result{}, err
	}
	return Result{Agent: agent, ConfigPath: path, Changed: true}, nil
}

func applyOpenCode(baseURL, key string, home string) (Result, error) {
	path := openCodePath(home)
	root, created, err := readJSONObject(path)
	if err != nil {
		return Result{}, err
	}

	s := loadState(home)
	e := entry{Agent: "opencode", ConfigPath: path, Created: created, Keys: map[string]keyState{}}
	if info, err := os.Stat(path); err == nil {
		e.Mode = uint32(info.Mode().Perm())
	}

	providerPath := []string{"provider", "tidegate"}
	prev, had := lookup(root, providerPath)
	e.Keys["provider.tidegate"] = keyState{Path: providerPath, Prev: prev, Had: had}

	opts := map[string]interface{}{"baseURL": baseURL}
	if key != "" {
		opts["apiKey"] = key
	}
	setPath(root, providerPath, map[string]interface{}{
		"npm":     "@ai-sdk/openai-compatible",
		"name":    "Tidegate",
		"options": opts,
	})

	mode := os.FileMode(0644)
	if key != "" {
		mode = 0600
	}
	if err := writeJSONObject(path, root, mode); err != nil {
		return Result{}, err
	}
	s.Entries["opencode"] = e
	if err := saveState(home, s); err != nil {
		return Result{}, err
	}
	return Result{Agent: "opencode", ConfigPath: path, Changed: true, Created: created}, nil
}

const (
	codexHeader      = "# >>> tidegate >>>"
	codexHeaderEnd   = "# <<< tidegate <<<"
	codexProvider    = "[model_providers.tidegate]"
	codexProviderEnd = "# <<< tidegate provider <<<"
)

func codexBlock(baseURL, key string) string {
	var b strings.Builder
	b.WriteString(codexHeader + "\n")
	b.WriteString("model_provider = \"tidegate\"\n")
	b.WriteString(codexHeaderEnd + "\n\n")
	b.WriteString("# >>> tidegate provider >>>\n")
	b.WriteString(codexProvider + "\n")
	b.WriteString("name = \"Tidegate\"\n")
	b.WriteString(fmt.Sprintf("base_url = %q\n", baseURL))
	if key != "" {
		b.WriteString(fmt.Sprintf("http_headers = { \"%s\" = %q }\n", "X-Tidegate-Key", key))
	} else {
		b.WriteString("env_key = \"OPENAI_API_KEY\"\n")
	}
	b.WriteString(codexProviderEnd + "\n")
	return b.String()
}

func applyCodex(baseURL, key string, home string) (Result, error) {
	path := codexPath(home)
	data, err := os.ReadFile(path)
	created := false
	if os.IsNotExist(err) {
		created = true
		data = nil
	} else if err != nil {
		return Result{}, err
	}
	body := string(data)

	if hasTOMLKey(body, "model_provider") {
		return Result{}, fmt.Errorf("%s already sets model_provider; point it at the tidegate provider manually", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return Result{}, err
	}
	backup := path + ".tidegate.bak"
	if !created {
		if err := os.WriteFile(backup, data, 0600); err != nil {
			return Result{}, err
		}
	}

	out := codexBlock(baseURL, key) + "\n" + strings.TrimLeft(body, "\n")
	mode := os.FileMode(0644)
	if key != "" {
		mode = 0600
	}
	if err := os.WriteFile(path, []byte(out), mode); err != nil {
		return Result{}, err
	}

	s := loadState(home)
	e := entry{Agent: "codex", ConfigPath: path, Created: created}
	if !created {
		e.Backup = backup
	}
	s.Entries["codex"] = e
	if err := saveState(home, s); err != nil {
		return Result{}, err
	}
	return Result{Agent: "codex", ConfigPath: path, Changed: true, Created: created}, nil
}

func removeCodex(home string) (Result, error) {
	path := codexPath(home)
	s := loadState(home)
	e, ok := s.Entries["codex"]
	if !ok {
		return Result{Agent: "codex", ConfigPath: path}, fmt.Errorf("no wrap state for codex (was it wrapped?)")
	}

	if e.Created {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return Result{}, err
		}
		if err == nil && !strings.Contains(string(data), codexHeader) {
			return Result{}, fmt.Errorf("%s was edited since wrapping; remove the tidegate block manually", path)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return Result{}, err
		}
	} else {
		out, err := stripMarkedBlocks(path)
		if err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(path, out, 0644); err != nil {
			return Result{}, err
		}
		if e.Backup != "" {
			_ = os.Remove(e.Backup)
		}
	}

	delete(s.Entries, "codex")
	if err := saveState(home, s); err != nil {
		return Result{}, err
	}
	return Result{Agent: "codex", ConfigPath: path, Changed: true}, nil
}

// stripMarkedBlocks removes Tidegate's marker-delimited regions.
func stripMarkedBlocks(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	skip := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case codexHeader, "# >>> tidegate provider >>>":
			skip = true
			continue
		case codexHeaderEnd, codexProviderEnd:
			skip = false
			continue
		}
		if !skip {
			out = append(out, line)
		}
	}
	// Collapse leading blank lines left behind by the removed block.
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	return []byte(strings.Join(out, "\n")), nil
}

// hasTOMLKey reports whether a top-level key is already set.
func hasTOMLKey(body, key string) bool {
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "[") {
			continue
		}
		if strings.HasPrefix(trimmed, key) {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, key))
			if strings.HasPrefix(rest, "=") {
				return true
			}
		}
	}
	return false
}
