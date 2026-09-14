// Package main is the Tidegate CLI entry point.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qo-roj/tidegate/internal/audit"
	"github.com/qo-roj/tidegate/internal/config"
	"github.com/qo-roj/tidegate/internal/ollama"
	"github.com/qo-roj/tidegate/internal/proxy"
	"github.com/qo-roj/tidegate/internal/route"
	"github.com/qo-roj/tidegate/internal/rules"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("tidegate %s\n", Version)
	case "start":
		cmdStart(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "classify":
		cmdClassify(os.Args[2:])
	case "dry-run":
		cmdDryRun(os.Args[2:])
	case "text":
		cmdText(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "config":
		cmdConfig(os.Args[2:])
	case "install":
		cmdInstall(os.Args[2:])
	case "setup-ollama":
		cmdSetupOllama()
	case "presets":
		cmdPresets()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`tidegate — redaction gateway for AI coding agents

Usage:
  tidegate <command> [flags]

Commands:
  start          Start the gateway proxy
  audit          Query the audit log
  classify       Test how a file would be classified
  text           Redact text/file/stdin for safe pasting (clean output)
  keygen         Generate a gateway client key (gateway mode)
  config         Edit or view configuration
  install        Configure an agent to use Tidegate
  setup-ollama   Configure local Ollama model
  presets        List available presets
  version        Show version

Run 'tidegate <command> --help' for command-specific flags.`)
}

func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("port", 0, "Gateway port (default: 8842)")
	preset := fs.String("preset", "", "Rule preset (desktop, server, paranoid)")
	bind := fs.String("bind", "", `Listen address (default: 127.0.0.1). Use 0.0.0.0 to serve the LAN in gateway mode (pair with --keyfile, [client:*] keys, or --require-key). "localhost" also selects loopback.`)
	certFile := fs.String("cert", "", "TLS certificate (PEM) — enables HTTPS listener when set with --key")
	keyFile := fs.String("key", "", "TLS private key (PEM) — enables HTTPS listener when set with --cert")
	keyfile := fs.String("keyfile", "", "Client keys file for gateway mode: lines of \"name key\" (comments with #). Enables gateway mode.")
	requireKey := fs.Bool("require-key", false, "Refuse unauthenticated requests even if no client keys are configured (blocks all requests — for testing/lockdown)")
	allowUnauth := fs.Bool("allow-unauth", false, "Serve on a non-loopback bind WITHOUT client keys (acknowledged risk: anyone on the network can use the gateway)")
	fs.Parse(args)

	cfg, err := config.Load(*port, *preset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// CLI overrides for gateway-mode settings (highest priority).
	if *bind != "" {
		cfg.Gateway.Bind = *bind
	}
	if *certFile != "" {
		cfg.Gateway.CertFile = *certFile
	}
	if *keyFile != "" {
		cfg.Gateway.KeyFile = *keyFile
	}
	var extraClients []config.Client
	if *keyfile != "" {
		extraClients, err = config.LoadKeyFile(*keyfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading keyfile: %v\n", err)
			os.Exit(1)
		}
	}
	// Merge keyfile clients. Same name in config and keyfile: the config
	// entry must fully REPLACE the keyfile entry — appending would keep
	// the old keyfile key valid after an operator rotates the key in the
	// config, defeating the rotation (review finding, deepseek #2).
	for _, ec := range extraClients {
		replaced := false
		for i := range cfg.Clients {
			if cfg.Clients[i].Name == ec.Name {
				cfg.Clients[i] = ec
				replaced = true
				break
			}
		}
		if !replaced {
			cfg.Clients = append(cfg.Clients, ec)
		}
	}

	// Gateway mode = listener reachable by other machines. Refuse to serve
	// unauthenticated on a non-loopback bind unless the operator explicitly
	// acknowledges it.
	loopback := isLoopback(cfg.Gateway.Bind)
	requireAuth := len(cfg.Clients) > 0 || *requireKey
	if !loopback && !requireAuth && !*allowUnauth {
		fmt.Fprintf(os.Stderr, "Refusing to bind %s without authentication.\n"+
			"Gateway mode needs client keys: use --keyfile <file>, or add\n"+
			"[client:<name>] sections with \"key = <value>\" to the config.\n"+
			"This protects your cloud API keys from anyone on the network.\n"+
			"To acknowledge the risk and serve unauthenticated anyway, add --allow-unauth.\n",
			cfg.Gateway.Bind)
		os.Exit(1)
	}

	fmt.Printf("🦞 Tidegate %s starting...\n", Version)
	if loopback {
		if len(cfg.Clients) > 0 {
			fmt.Printf("   Mode: single-machine (loopback) + client keys enabled\n")
		} else {
			fmt.Printf("   Mode: single-machine (loopback)\n")
		}
	} else {
		fmt.Printf("   Mode: GATEWAY — serving %s\n", cfg.Gateway.Bind)
		if len(cfg.Clients) > 0 {
			fmt.Printf("   Auth: %d client(s), X-Tidegate-Key required\n", len(cfg.Clients))
		} else if *allowUnauth {
			fmt.Printf("   Auth: DISABLED (--allow-unauth) — unauthenticated gateway, use only on trusted networks\n")
		}
	}
	if cfg.Gateway.CertFile != "" && cfg.Gateway.KeyFile != "" {
		fmt.Printf("   TLS: enabled (cert %s)\n", cfg.Gateway.CertFile)
	}
	fmt.Printf("   Port: %d\n", cfg.Gateway.Port)
	fmt.Printf("   Preset: %s\n", cfg.Gateway.Preset)
	fmt.Printf("   Ollama: %s (%s)\n", cfg.Local.OllamaURL, cfg.Local.OllamaModel)
	fmt.Println()

	// Initialize audit log
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".local", "share", "tidegate")
	os.MkdirAll(dataDir, 0755)
	dbPath := filepath.Join(dataDir, "audit.db")
	auditLog, err := audit.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit log: %v\n", err)
		os.Exit(1)
	}
	defer auditLog.Close()

	// Initialize Ollama client
	ollamaClient := ollama.New(cfg.Local.OllamaURL, cfg.Local.OllamaModel)
	if ollamaClient.Available() {
		fmt.Printf("   Ollama: ✓ available (%s)\n", cfg.Local.OllamaModel)
	} else {
		fmt.Printf("   Ollama: ✗ not available (local-only content will be blocked)\n")
	}

	// Initialize router
	router := route.New(cfg.RuleSet, ollamaClient, auditLog)

	// Initialize and start proxy
	srv := proxy.New(router, auditLog, cfg.Gateway.Port)
	srv.Bind = cfg.Gateway.Bind
	srv.CertFile = cfg.Gateway.CertFile
	srv.KeyFile = cfg.Gateway.KeyFile
	srv.RequireKey = *requireKey
	for _, c := range cfg.Clients {
		srv.Clients = append(srv.Clients, proxy.Client{Name: c.Name, Key: c.Key})
	}
	fmt.Println()
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
		os.Exit(1)
	}
}

// isLoopback reports whether the bind address listens on loopback only.
// Uses net.ParseIP().IsLoopback() so the whole 127.0.0.0/8 range,
// ::1, and IPv4-mapped IPv6 loopback are recognized — string matching
// only caught a few spellings (review finding).
func isLoopback(bind string) bool {
	switch bind {
	case "", "localhost", "loopback":
		return true
	}
	host := bind
	if h, _, err := net.SplitHostPort(bind); err == nil {
		host = h // tolerate "127.0.0.1:8842" style input
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	live := fs.Bool("live", false, "Tail -f style live mode (alias for --tail)")
	tail := fs.Bool("tail", false, "Tail mode: show recent entries and poll for new ones")
	watch := fs.Bool("watch", false, "Watch mode: same as --tail but with more detail")
	since := fs.String("since", "24h", "Time range (e.g. 2h, 24h, 7d)")
	limit := fs.Int("limit", 100, "Maximum entries to show")
	export := fs.String("export", "", "Export audit log to JSON file")
	rotate := fs.String("rotate", "", "Export to JSON file and delete old entries from DB")
	agentFilter := fs.String("agent", "", "Filter by agent name")
	fs.Parse(args)

	home, _ := os.UserHomeDir()
	dbPath := home + "/.local/share/tidegate/audit.db"

	log, err := audit.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit log: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	// Export mode
	if *export != "" {
		count, err := log.Export(*export, parseSince(*since))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Exported %d entries to %s\n", count, *export)
		return
	}

	// Rotate mode
	if *rotate != "" {
		count, err := log.Rotate(*rotate, parseSince(*since))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error rotating: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Rotated %d entries to %s (deleted from DB)\n", count, *rotate)
		return
	}

	// Live/tail/watch mode — poll for new entries
	if *tail || *watch || *live {
		auditLive(log, *agentFilter, *watch)
		return
	}

	// Standard query mode
	entries, err := log.Query(*agentFilter, parseSince(*since), *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying audit log: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return
	}

	for _, e := range entries {
		printAuditEntry(e, false)
	}
}

// auditLive polls the audit log for new entries and prints them as they arrive.
func auditLive(log *audit.Log, agentFilter string, detailed bool) {
	// Start from now
	lastSeen := time.Now()

	// Show recent history first (last 10 entries)
	recent, _ := log.Query(agentFilter, time.Now().Add(-5*time.Minute), 10)
	for i := len(recent) - 1; i >= 0; i-- {
		printAuditEntry(recent[i], detailed)
	}
	if len(recent) > 0 {
		lastSeen = recent[0].Timestamp
	}

	fmt.Fprintln(os.Stderr, "\n── watching for new entries (Ctrl+C to stop) ──")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		entries, err := log.Query(agentFilter, lastSeen, 1000)
		if err != nil {
			continue
		}
		for _, e := range entries {
			printAuditEntry(e, detailed)
			if e.Timestamp.After(lastSeen) {
				lastSeen = e.Timestamp
			}
		}
	}
}

// printAuditEntry prints a single audit entry.
func printAuditEntry(e audit.Entry, detailed bool) {
	approved := "✗"
	if e.Approved {
		approved = "✓"
	}
	if detailed {
		fmt.Printf("%s  %s  %s  %s  %s  tier=%s  %s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Agent, e.Provider, e.Action, e.Target, e.Tier, approved)
		if e.Redactions != "" && e.Redactions != "null" {
			fmt.Printf("  redactions: %s\n", e.Redactions)
		}
		if e.Notes != "" {
			fmt.Printf("  notes: %s\n", e.Notes)
		}
	} else {
		fmt.Printf("%s  %s  %s  %s  %s  tier=%s  %s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Agent, e.Provider, e.Action, e.Target, e.Tier, approved)
	}
}

func cmdClassify(args []string) {
	fs := flag.NewFlagSet("classify", flag.ExitOnError)
	fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tidegate classify <path>")
		os.Exit(1)
	}

	path := fs.Arg(0)
	cfg, err := config.Load(0, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	tier, source := cfg.RuleSet.ClassifyPath(path)
	fmt.Printf("path:   %s\n", path)
	fmt.Printf("tier:   %s\n", tier)
	fmt.Printf("source: %s\n", source)

	if tier == rules.TierRedacted {
		fmt.Println()
		fmt.Println("Redaction patterns would be applied to this content.")
		fmt.Println("Use 'tidegate dry-run --file <path>' to see redacted output.")
	}
}

func cmdConfig(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: tidegate config [edit|show|set <key> <value>]")
		return
	}

	switch args[0] {
	case "edit":
		home, _ := os.UserHomeDir()
		path := home + "/.config/tidegate/tidegate.conf"
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		fmt.Printf("Opening %s with %s\n", path, editor)
		// In production, exec the editor. For now just show the path.
		fmt.Println("(editor exec not yet implemented)")
	case "show":
		home, _ := os.UserHomeDir()
		path := home + "/.config/tidegate/tidegate.conf"
		if _, err := os.Stat(path); err != nil {
			fmt.Println("No config file found. Using defaults.")
			return
		}
		data, _ := os.ReadFile(path)
		fmt.Print(string(data))
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: tidegate config set <key> <value>")
			return
		}
		fmt.Printf("Setting %s = %s (not yet implemented)\n", args[1], args[2])
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
	}
}

// cmdDryRun shows what the redactor would do to a file (or stdin) without
// sending anything anywhere. Prints before/after and the token mapping.
func cmdDryRun(args []string) {
	fs := flag.NewFlagSet("dry-run", flag.ExitOnError)
	file := fs.String("file", "", "File to redact (default: read stdin)")
	unified := fs.Bool("unified", false, "Unified diff instead of side-by-side listing")
	restore := fs.Bool("restore", false, "Also show the restored output (tokens mapped back)")
	fs.Parse(args)

	var data []byte
	var err error
	if *file != "" {
		data, err = os.ReadFile(*file)
	} else if stdinIsPiped() {
		data, err = io.ReadAll(os.Stdin)
	} else {
		// No file and no piped input: refuse instead of blocking on the
		// terminal, matching `text` behavior.
		fmt.Fprintln(os.Stderr, "Usage: tidegate dry-run --file <path> | (piped stdin)\nShows what redaction would do to a file or piped text, without sending anything anywhere.")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load(0, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	router := route.New(cfg.RuleSet, nil, nil)
	redactor := router.NewRedactor()
	defer redactor.Clear()

	content := string(data)
	after, summary := redactor.Redact(content)

	fmt.Printf("Input: %d bytes, %d lines\n\n", len(data), strings.Count(content, "\n")+1)

	if *unified {
		fmt.Println("── UNIFIED DIFF (before → after) ──")
		beforeLines := strings.Split(content, "\n")
		afterLines := strings.Split(after, "\n")
		n := len(beforeLines)
		if len(afterLines) > n {
			n = len(afterLines)
		}
		for i := 0; i < n; i++ {
			b, a := "", ""
			if i < len(beforeLines) {
				b = beforeLines[i]
			}
			if i < len(afterLines) {
				a = afterLines[i]
			}
			if b == a {
				continue
			}
			fmt.Printf("- %s\n+ %s\n", b, a)
		}
	} else {
		fmt.Println("── BEFORE / AFTER ──")
		beforeLines := strings.Split(content, "\n")
		afterLines := strings.Split(after, "\n")
		n := len(beforeLines)
		if len(afterLines) > n {
			n = len(afterLines)
		}
		for i := 0; i < n; i++ {
			b, a := "", ""
			if i < len(beforeLines) {
				b = beforeLines[i]
			}
			if i < len(afterLines) {
				a = afterLines[i]
			}
			if b == a {
				fmt.Printf("  %s\n", b)
			} else {
				fmt.Printf("- %s\n+ %s\n", b, a)
			}
		}
	}

	fmt.Println("\n── REDACTION SUMMARY ──")
	if summary.Total() == 0 {
		fmt.Println("nothing redacted")
	} else {
		// Deterministic order for readable output
		names := make([]string, 0, len(summary))
		for name := range summary {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("  %-20s %d\n", name, summary[name])
		}
		fmt.Printf("  %-20s %d\n", "TOTAL", summary.Total())
	}

	if *restore {
		restored := redactor.Restore(after)
		if restored == content {
			fmt.Println("\n── RESTORE CHECK ──\nround-trip identical to input")
		} else {
			fmt.Println("\n── RESTORE CHECK ──")
			fmt.Println(restored)
		}
	}
}

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	all := fs.Bool("all", false, "Configure all detected agents")
	agent := fs.String("agent", "", "Configure a specific agent")
	dryRun := fs.Bool("dry-run", false, "Show changes without applying")
	fs.Parse(args)

	if *all {
		fmt.Println("Detecting installed agents...")
		fmt.Println("(not yet implemented)")
		return
	}

	if *agent != "" {
		dryStr := ""
		if *dryRun {
			dryStr = " (dry run)"
		}
		fmt.Printf("Configuring agent: %s%s\n", *agent, dryStr)
		fmt.Println("(not yet implemented)")
		return
	}

	fmt.Println("Usage: tidegate install --all | --agent <name>")
}

func cmdSetupOllama() {
	fmt.Println("🦞 Tidegate — Ollama Setup")
	fmt.Println("(not yet implemented — see scripts/ollama-setup.sh)")
}

func cmdPresets() {
	fmt.Println("Available presets:")
	fmt.Println("  desktop         — Omarchy / personal workstation (default)")
	fmt.Println("  server          — Production server with user data")
	fmt.Println("  paranoid        — Maximum redaction, minimal cloud exposure")
	fmt.Println("  training-data   — Redact all PII for safe fine-tuning datasets")
}

func parseSince(s string) time.Time {
	// Parse duration strings like "24h", "2h", "7d"
	if s == "" {
		return time.Time{}
	}
	// Convert "7d" to "168h" etc.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		numStr := s[:len(s)-1]
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return time.Now().Add(-24 * time.Hour)
		}
		s = fmt.Sprintf("%dh", n*24)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		// Default: 24h
		d = 24 * time.Hour
	}
	return time.Now().Add(-d)
}
