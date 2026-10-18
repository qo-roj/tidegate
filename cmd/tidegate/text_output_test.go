package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression 2026-09-07 review: os.WriteFile applies its mode only at file
// creation — writing redacted output into a pre-existing 0644 file left the
// content world-readable. The mode must be forced after the write.
func TestWriteTextOutputForces0600OnExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(p, []byte("old world-readable content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeTextOutput("redacted [TG:EMAIL:1:00000000] content", p); err != nil {
		t.Fatalf("writeTextOutput: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("output file mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "redacted [TG:EMAIL:1:00000000] content" {
		t.Errorf("content = %q", data)
	}
}

func TestWriteTextOutputNewFileIs0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fresh.txt")
	if err := writeTextOutput("x", p); err != nil {
		t.Fatalf("writeTextOutput: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("new file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSamePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}

	if !samePath(p, p) {
		t.Error("identical path should be same")
	}
	if !samePath(p, link) {
		t.Error("symlink to the file should be same")
	}
	if !samePath(p, filepath.Join(dir, "..", filepath.Base(dir), "a.txt")) {
		t.Error("relative/../ traversal to the same file should be same")
	}
	other := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(other, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if samePath(p, other) {
		t.Error("different files must not be same")
	}
}
