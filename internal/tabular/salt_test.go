package tabular

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateSalt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "tabular.salt")

	first, err := LoadOrCreateSalt(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(first) != SaltSize*2 {
		t.Fatalf("salt length = %d, want %d hex chars", len(first), SaltSize*2)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("salt file mode = %o, want 600", perm)
	}

	second, err := LoadOrCreateSalt(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if second != first {
		t.Error("second call regenerated the salt")
	}

	other, err := LoadOrCreateSalt(filepath.Join(t.TempDir(), "tabular.salt"))
	if err != nil {
		t.Fatalf("other load: %v", err)
	}
	if other == first {
		t.Error("two installs generated the same salt")
	}
}

func TestLoadOrCreateSaltRejectsShortFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tabular.salt")
	if err := os.WriteFile(path, []byte("abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSalt(path); err == nil {
		t.Fatal("short salt file must be rejected, not used")
	}
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"off":      ModeOff,
		"":         ModeOff,
		"typo":     ModeOff,
		"shadow":   ModeShadow,
		"dry-run":  ModeShadow,
		"apply":    ModeApply,
		"enforce":  ModeApply,
		"  APPLY ": ModeApply,
	}
	for in, want := range cases {
		if got := ParseMode(in); got != want {
			t.Errorf("ParseMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFingerprintTracksPolicy(t *testing.T) {
	base := Options{Salt: "one", SigFigs: 2, Drop: []string{"card"}}
	if got := base.Fingerprint(); got != (Options{Salt: "one", SigFigs: 2, Drop: []string{"card"}}).Fingerprint() {
		t.Error("fingerprint is not stable")
	}
	if base.Fingerprint() == (Options{Salt: "two", SigFigs: 2, Drop: []string{"card"}}).Fingerprint() {
		t.Error("salt change did not change the fingerprint")
	}
	if base.Fingerprint() == (Options{Salt: "one", SigFigs: 3, Drop: []string{"card"}}).Fingerprint() {
		t.Error("sig-figs change did not change the fingerprint")
	}
	if base.Fingerprint() == (Options{Salt: "one", SigFigs: 2, Drop: []string{"ssn"}}).Fingerprint() {
		t.Error("column policy change did not change the fingerprint")
	}
	if base.Fingerprint() == (Options{Salt: "one", SigFigs: 2, Drop: []string{"card"}, Disable: map[string]bool{"date": true}}).Fingerprint() {
		t.Error("generalizer toggle did not change the fingerprint")
	}
}

func TestLoadOrCreateSaltLeavesExistingDirAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "preexisting")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSalt(filepath.Join(dir, "tabular.salt")); err != nil {
		t.Fatalf("LoadOrCreateSalt: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("pre-existing directory mode changed to %o, want 755", perm)
	}
}

func TestLoadOrCreateSaltRejectsRelativePath(t *testing.T) {
	if _, err := LoadOrCreateSalt("relative/tabular.salt"); err == nil {
		t.Fatal("relative salt path accepted")
	}
}
