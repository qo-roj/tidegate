package tabular

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Mode is the gateway's policy for generalized tables. It lives here so the
// proxy, the CLI and the config parser agree on one vocabulary.
type Mode int

const (
	// ModeOff forwards tables untouched.
	ModeOff Mode = iota
	// ModeShadow classifies and generalizes but forwards the original bytes,
	// recording what would have changed. This is the rollout default.
	ModeShadow
	// ModeApply rewrites the table before it leaves the machine.
	ModeApply
)

func (m Mode) String() string {
	switch m {
	case ModeShadow:
		return "shadow"
	case ModeApply:
		return "apply"
	default:
		return "off"
	}
}

// ParseMode reads a config value. Unknown values return ModeOff: a typo must
// not silently turn rewriting on.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "shadow", "log", "dry-run", "dryrun":
		return ModeShadow
	case "apply", "on", "true", "yes", "enforce":
		return ModeApply
	default:
		return ModeOff
	}
}

// Fingerprint identifies the effective generalization policy: salt, thresholds
// and column policy. The redaction cache keys on it, so changing any of these
// must not serve output produced under the old settings.
func (o Options) Fingerprint() string {
	o = o.withDefaults()
	parts := []string{
		"salt:" + sumHex(o.Salt),
		fmt.Sprintf("min:%d", o.MinRows),
		fmt.Sprintf("sig:%d", o.SigFigs),
		fmt.Sprintf("cat:%d", o.MaxCategorical),
		"text:" + o.Text,
		"keep:" + strings.Join(o.Keep, "|"),
		"drop:" + strings.Join(o.Drop, "|"),
	}
	for _, k := range []string{"email", "ip", "phone", "card", "ssn", "uuid", "url", "date", "number", "text"} {
		if o.Disable[k] {
			parts = append(parts, "off:"+k)
		}
	}
	return sumHex(strings.Join(parts, "\x00"))[:16]
}

func sumHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SaltSize is the number of random bytes in a generated salt.
const SaltSize = 32

// LoadOrCreateSalt reads the per-install salt, generating it on first use.
// The file is created 0600 in a 0700 directory: labels are hashes of real
// values, so the salt is the only thing standing between a label and a
// dictionary attack on a known email address.
func LoadOrCreateSalt(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("tabular salt path is empty")
	}

	if salt, err := readSalt(path); err == nil {
		return salt, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("creating salt directory: %w", err)
	}
	buf := make([]byte, SaltSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	salt := hex.EncodeToString(buf)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Another process won the race; use its salt.
			return readSalt(path)
		}
		return "", fmt.Errorf("creating salt file: %w", err)
	}
	if _, err := f.WriteString(salt + "\n"); err != nil {
		f.Close()
		return "", fmt.Errorf("writing salt file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing salt file: %w", err)
	}
	return salt, nil
}

func readSalt(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	salt := strings.TrimSpace(string(data))
	if len(salt) < 16 {
		return "", fmt.Errorf("salt file %s is too short (%d chars), refusing to use it", path, len(salt))
	}
	return salt, nil
}
