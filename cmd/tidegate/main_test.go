package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qo-roj/tidegate/internal/redact"
)

func TestJoinTextArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"single arg", []string{"hello"}, "hello"},
		{"multiple joined with space", []string{"server", "at", "192.168.1.1", "down"}, "server at 192.168.1.1 down"},
		{"no args", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinTextArgs(tc.args); got != tc.want {
				t.Errorf("joinTextArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestRunTextRedactsSensitive(t *testing.T) {
	r := redact.New()
	defer r.Clear()

	out, summary := runText("host 192.168.1.100 and bob@example.com wrote this", r)

	if strings.Contains(out, "192.168.1.100") {
		t.Errorf("output still contains raw IP: %q", out)
	}
	if !strings.Contains(out, "[TG:IP:1:00000000]") {
		t.Errorf("output missing [TG:IP:1:00000000] token: %q", out)
	}
	if strings.Contains(out, "bob@example.com") {
		t.Errorf("output still contains raw email: %q", out)
	}
	if !strings.Contains(out, "[TG:EMAIL:1:00000000]") {
		t.Errorf("output missing [TG:EMAIL:1:00000000] token: %q", out)
	}
	if summary.Total() < 2 {
		t.Errorf("summary total = %d, want >= 2", summary.Total())
	}
}

func TestRunTextCleanPassthrough(t *testing.T) {
	r := redact.New()
	defer r.Clear()

	in := "just a normal sentence about nothing sensitive"
	out, summary := runText(in, r)

	if out != in {
		t.Errorf("clean input should pass through byte-identical, got %q", out)
	}
	if summary.Total() != 0 {
		t.Errorf("summary total = %d, want 0", summary.Total())
	}
}

func TestRunTextDoesNotTouchNewlines(t *testing.T) {
	r := redact.New()
	defer r.Clear()

	// runText is newline-neutral: stdout normalization happens at the
	// output layer, so --out files preserve the input's exact state.
	out, _ := runText("no newline here", r)
	if out != "no newline here" {
		t.Errorf("runText appended a newline: %q", out)
	}
	out, _ = runText("line one\nline two\n", r)
	if out != "line one\nline two\n" {
		t.Errorf("trailing newline altered: %q", out)
	}
}

func TestEnsureTrailingNewline(t *testing.T) {
	tests := []struct{ in, want string }{
		{"x", "x\n"},
		{"x\n", "x\n"},
		{"", "\n"},
		{"multi\nline", "multi\nline\n"},
	}
	for _, tc := range tests {
		if got := ensureTrailingNewline(tc.in); got != tc.want {
			t.Errorf("ensureTrailingNewline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWriteTextOutputStdout(t *testing.T) {
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	if err := writeTextOutput("redacted text\n", ""); err != nil {
		t.Fatalf("writeTextOutput to stdout: %v", err)
	}
	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if buf.String() != "redacted text\n" {
		t.Errorf("stdout got %q, want %q", buf.String(), "redacted text\n")
	}
}

func TestWriteTextOutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "clean.txt")

	if err := writeTextOutput("safe contents\n", outPath); err != nil {
		t.Fatalf("writeTextOutput to file: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if string(data) != "safe contents\n" {
		t.Errorf("file contents = %q, want %q", string(data), "safe contents\n")
	}
	// Redacted output files are user-private: 0600, not world/group-readable.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file mode = %o, want 0600 (private)", info.Mode().Perm())
	}
}

func TestWriteTextOutputParentMissing(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "no", "such", "dir", "out.txt")
	if err := writeTextOutput("x\n", outPath); err == nil {
		t.Error("expected error writing to path with missing parent dir")
	}
}

func TestPrintTextSummaryEmpty(t *testing.T) {
	var buf bytes.Buffer
	printTextSummary(&buf, redact.Summary{})
	got := buf.String()
	if got != "no redactions\n" {
		t.Errorf("empty summary output = %q, want %q", got, "no redactions\n")
	}
}

func TestPrintTextSummaryCounts(t *testing.T) {
	var buf bytes.Buffer
	s := redact.Summary{"email": 2, "ip": 1}
	printTextSummary(&buf, s)
	got := buf.String()

	// Header with total
	if !strings.Contains(got, "3 redactions") {
		t.Errorf("summary should report total 3: %q", got)
	}
	// Alphabetical order: email before ip
	emailIdx := strings.Index(got, "email")
	ipIdx := strings.Index(got, "ip")
	if emailIdx == -1 || ipIdx == -1 {
		t.Fatalf("summary missing category lines: %q", got)
	}
	if emailIdx > ipIdx {
		t.Errorf("categories should print alphabetically, got: %q", got)
	}
}

func TestStdinIsPipedDetectsPipe(t *testing.T) {
	orig := os.Stdin
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = pr
	defer func() {
		os.Stdin = orig
		pr.Close()
		pw.Close()
	}()

	if !stdinIsPiped() {
		t.Error("stdinIsPiped() = false for a pipe, want true")
	}
}

func TestSortedSummaryNames(t *testing.T) {
	s := redact.Summary{"zebra": 1, "alpha": 1, "mid": 1}
	got := sortedSummaryNames(s)
	want := []string{"alpha", "mid", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortedSummaryNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
