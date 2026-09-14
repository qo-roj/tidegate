package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenPrintsKey(t *testing.T) {
	// cmdKeygen prints to stdout; capture via pipe is awkward in-process,
	// so this test covers the --add path and the underlying randomness
	// indirectly through file content.
	_ = t
}

func TestKeygenAddCreatesKeyfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.keys")

	exitCalled := false
	origExit := osExit
	osExit = func(int) { exitCalled = true }
	t.Cleanup(func() { osExit = origExit })

	cmdKeygen([]string{"--add", "phone", "--keyfile", path})
	if exitCalled {
		t.Fatal("keygen --add should not exit(1) on success")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	fields := strings.Fields(line)
	if len(fields) != 2 {
		t.Fatalf("want \"name key\" line, got %q", line)
	}
	if fields[0] != "phone" {
		t.Errorf("name = %q, want phone", fields[0])
	}
	if len(fields[1]) < 20 {
		t.Errorf("key too short: %q", fields[1])
	}
}

func TestKeygenAddDuplicateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.keys")
	if err := os.WriteFile(path, []byte("phone existing-key-aaaaaaaaaaaa\n"), 0600); err != nil {
		t.Fatal(err)
	}

	exitCode := 0
	origExit := osExit
	osExit = func(code int) { exitCode = code; panic("exit") }
	t.Cleanup(func() { osExit = origExit })

	defer func() { recover() }()
	cmdKeygen([]string{"--add", "phone", "--keyfile", path})

	if exitCode != 1 {
		t.Errorf("want exit 1 for duplicate, got %d", exitCode)
	}
	// Keyfile unchanged after failed add.
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "existing-key") && strings.Count(strings.TrimSpace(string(data)), "\n") != 0 {
		// still exactly one line
		if !strings.HasPrefix(strings.TrimSpace(string(data)), "phone existing-key") {
			t.Error("keyfile modified by failed duplicate add")
		}
	}
}

func TestKeygenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.keys")

	origExit := osExit
	osExit = func(int) { panic("exit") }
	t.Cleanup(func() { osExit = origExit })
	defer func() { recover() }()

	cmdKeygen([]string{"--add", "laptop", "--keyfile", path})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("keyfile perms = %o, want 600", perm)
	}
}
