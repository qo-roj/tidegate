package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/qo-roj/tidegate/internal/config"
	"github.com/qo-roj/tidegate/internal/redact"
	"github.com/qo-roj/tidegate/internal/route"
)

// cmdText redacts free-form text: arguments, a file, or stdin. Output is
// clean redacted text on stdout (or --out file), suitable for pasting into
// web UIs (ChatGPT, etc.) or sharing. Use dry-run for a before/after view.
func cmdText(args []string) {
	fs := flag.NewFlagSet("text", flag.ExitOnError)
	file := fs.String("file", "", "Redact a file instead of text arguments")
	out := fs.String("out", "", "Write result to this file instead of stdout")
	preset := fs.String("preset", "", "Rule preset (desktop, server, paranoid, training-data)")
	summary := fs.Bool("summary", false, "Print what was redacted to stderr")
	fs.Parse(args)

	// Go's flag parser stops at the first positional argument, so a flag
	// typed AFTER the text ends up in fs.Args() un-parsed and would be
	// silently redacted into the output. Detect and fail loudly instead.
	positionals, flagAfterText := splitTextArgs(fs.Args())
	if flagAfterText != "" {
		if len(positionals) == 0 {
			fmt.Fprintf(os.Stderr, "Error: %s is not a tidegate text flag and no text was given.\nUsage: tidegate text [flags] \"your text\"\n", flagAfterText)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %s appears after the text.\nFlags go before it: tidegate text %s \"your text\"\n", flagAfterText, flagAfterText)
		}
		os.Exit(1)
	}

	// --file and positional text are mutually exclusive; silently dropping
	// one input would be surprising (and a leak risk if the drop goes
	// unnoticed).
	if *file != "" && len(positionals) > 0 {
		fmt.Fprintln(os.Stderr, "Error: --file and text arguments are mutually exclusive; pass one or the other.")
		os.Exit(1)
	}

	// --out must differ from --file: writing the redacted output over the
	// input silently destroys the original. Tolerates relative paths and
	// symlinks pointing at the input.
	if *file != "" && *out != "" && samePath(*file, *out) {
		fmt.Fprintln(os.Stderr, "Error: --out must be a different file than --file (the original would be overwritten).")
		os.Exit(1)
	}

	var content string
	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", *file, err)
			os.Exit(1)
		}
		content = string(data)
	} else if len(positionals) > 0 {
		content = joinTextArgs(positionals)
	} else if stdinIsPiped() {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		content = string(data)
	} else {
		fmt.Fprintln(os.Stderr, `Usage: tidegate text "some text" | --file <path> | (piped stdin)
Redacts sensitive data (IPs, emails, keys...) so it is safe to paste anywhere.`)
		os.Exit(1)
	}

	cfg, err := config.Load(0, *preset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	router := route.New(cfg.RuleSet, nil, nil)
	redactor := router.NewRedactor()
	defer redactor.Clear()

	result, s := runText(content, redactor)

	if err := writeTextOutput(result, *out); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	if *summary {
		printTextSummary(os.Stderr, s)
	}
}

// joinTextArgs joins positional arguments into one text string.
func joinTextArgs(args []string) string {
	return strings.Join(args, " ")
}

// splitTextArgs takes the positional arguments left after flag parsing and
// returns the text portion plus the name of any flag that was typed after
// the text (Go's parser stops at the first positional, so such flags arrive
// here un-parsed and would otherwise be silently redacted into the output).
// Only long flags (--word) count — a bare "-" or short "-u" in prose is
// far more likely to be text than a tidegate flag.
func splitTextArgs(positionals []string) (text []string, flagAfterText string) {
	for i, a := range positionals {
		if strings.HasPrefix(a, "--") && len(a) > 2 {
			return positionals[:i], a
		}
	}
	return positionals, ""
}

// runText redacts content and returns the result newline-untouched. Stdout
// normalization (one trailing newline) happens in the output layer so that
// --out files preserve the input's exact newline state.
func runText(content string, r *redact.Redactor) (string, redact.Summary) {
	return route.ApplyShapeRedaction(content, r)
}

// ensureTrailingNewline returns s with exactly one terminal newline, for
// terminal/stdout display only.
func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// writeTextOutput writes the redacted text to outPath, or stdout when empty.
// Stdout gets a normalized trailing newline (terminal display); files keep
// the content byte-exact as produced by runText.
// Parent directories are NOT created — a missing parent is an error, matching
// Unix convention (no silent directory creation from a typo'd path).
// Files are written 0600: output of a redaction tool may still contain
// context the user considers private, and umask-based 0644 would leave it
// world-readable. The mode is forced explicitly after the write because the
// O_CREATE mode only applies to newly created files — a pre-existing 0644
// file would otherwise keep its permissions.
func writeTextOutput(s string, outPath string) error {
	if outPath == "" {
		_, err := os.Stdout.WriteString(ensureTrailingNewline(s))
		return err
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(outPath, 0600)
}

// samePath reports whether two paths refer to the same file, tolerating
// relative paths and symlinks on the final element.
func samePath(a, b string) bool {
	abs := func(p string) string {
		ap, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return ap
	}
	ra, rb := abs(a), abs(b)
	if ra == rb {
		return true
	}
	ia, erra := os.Stat(ra)
	ib, errb := os.Stat(rb)
	return erra == nil && errb == nil && os.SameFile(ia, ib)
}

// printTextSummary prints a compact "what was redacted" listing to w.
func printTextSummary(w io.Writer, s redact.Summary) {
	if s.Total() == 0 {
		fmt.Fprintln(w, "no redactions")
		return
	}
	fmt.Fprintf(w, "%d redactions\n", s.Total())
	for _, name := range sortedSummaryNames(s) {
		fmt.Fprintf(w, "  %s: %d\n", name, s[name])
	}
}

// stdinIsPiped reports whether stdin is piped/redirected (not a terminal).
func stdinIsPiped() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

// sortedSummaryNames returns the summary's category names in sorted order.
func sortedSummaryNames(s redact.Summary) []string {
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
