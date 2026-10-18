package redact

import (
	"strings"
	"testing"
)

func TestRedactIPv4(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "The server is at 203.0.113.42 and the DB is at 10.0.0.1"
	redacted, summary := r.Redact(content)

	if summary["ipv4"] != 2 {
		t.Errorf("expected 2 IPv4 redactions, got %d", summary["ipv4"])
	}
	if strings.Contains(redacted, "203.0.113.42") {
		t.Error("redacted content still contains original IP")
	}
	if strings.Contains(redacted, "10.0.0.1") {
		t.Error("redacted content still contains original IP")
	}
	if !strings.Contains(redacted, "[TG:IP:") {
		t.Error("redacted content missing token")
	}
}

// TestRedactDistinctValuesGetDistinctTokens is a regression test for the
// critical bug where ReplaceAllString collapsed all distinct values matching
// the same pattern to a single token. Two different IPs should get two
// different tokens, and Restore() should map each back to the correct value.
func TestRedactDistinctValuesGetDistinctTokens(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Server A is 203.0.113.42, server B is 10.0.0.1, server C is 203.0.113.42"
	redacted, summary := r.Redact(content)

	if summary["ipv4"] != 3 {
		t.Errorf("expected 3 IPv4 matches, got %d", summary["ipv4"])
	}

	// Two distinct IPs should get two distinct tokens
	tokenA := "[TG:IP:1:00000000]"
	tokenB := "[TG:IP:2:00000000]"
	if !strings.Contains(redacted, tokenA) {
		t.Errorf("expected token %s in redacted output: %s", tokenA, redacted)
	}
	if !strings.Contains(redacted, tokenB) {
		t.Errorf("expected token %s in redacted output: %s", tokenB, redacted)
	}

	// Restore should map each token back to the correct IP
	restored := r.Restore(redacted)
	if !strings.Contains(restored, "203.0.113.42") {
		t.Error("Restore should contain 203.0.113.42")
	}
	if !strings.Contains(restored, "10.0.0.1") {
		t.Error("Restore should contain 10.0.0.1")
	}
	// The duplicate IP should appear twice in the restored output
	count := strings.Count(restored, "203.0.113.42")
	if count != 2 {
		t.Errorf("expected 203.0.113.42 to appear 2 times in restored, got %d", count)
	}
}

func TestRedactEmail(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Contact admin@example.com or support@myapp.com for help"
	redacted, summary := r.Redact(content)

	if summary["email"] != 2 {
		t.Errorf("expected 2 email redactions, got %d", summary["email"])
	}
	if strings.Contains(redacted, "admin@example.com") {
		t.Error("redacted content still contains email")
	}
	if !strings.Contains(redacted, "[TG:EMAIL:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactGitHubToken(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
	redacted, summary := r.Redact(content)

	if summary["api_key_github"] != 1 {
		t.Errorf("expected 1 GitHub token redaction, got %d", summary["api_key_github"])
	}
	if strings.Contains(redacted, "ghp_") {
		t.Error("redacted content still contains GitHub token")
	}
	if !strings.Contains(redacted, "[TG:TOKEN:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactOpenAIToken(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	redacted, summary := r.Redact(content)

	if summary["api_key_openai"] != 1 {
		t.Errorf("expected 1 OpenAI token redaction, got %d", summary["api_key_openai"])
	}
	if strings.Contains(redacted, "sk-proj-") {
		t.Error("redacted content still contains OpenAI token")
	}
	if !strings.Contains(redacted, "[TG:TOKEN:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactAnthropicToken(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCD"
	redacted, summary := r.Redact(content)

	if summary["api_key_anthropic"] != 1 {
		t.Errorf("expected 1 Anthropic token redaction, got %d", summary["api_key_anthropic"])
	}
	if strings.Contains(redacted, "sk-ant-") {
		t.Error("redacted content still contains Anthropic token")
	}
	if !strings.Contains(redacted, "[TG:TOKEN:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactAWSToken(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	redacted, summary := r.Redact(content)

	if summary["api_key_aws"] != 1 {
		t.Errorf("expected 1 AWS token redaction, got %d", summary["api_key_aws"])
	}
	if strings.Contains(redacted, "AKIA") {
		t.Error("redacted content still contains AWS token")
	}
	if !strings.Contains(redacted, "[TG:TOKEN:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactJWT(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	redacted, summary := r.Redact(content)

	if summary["jwt"] != 1 {
		t.Errorf("expected 1 JWT redaction, got %d", summary["jwt"])
	}
	if strings.Contains(redacted, "eyJ") {
		t.Error("redacted content still contains JWT")
	}
	if !strings.Contains(redacted, "[TG:JWT:") {
		t.Error("redacted content missing token")
	}
}

func TestRedactPrivateKey(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz\n-----END RSA PRIVATE KEY-----"
	redacted, summary := r.Redact(content)

	if summary["private_key"] != 1 {
		t.Errorf("expected 1 private key redaction, got %d", summary["private_key"])
	}
	if strings.Contains(redacted, "BEGIN RSA PRIVATE KEY") {
		t.Error("redacted content still contains private key block")
	}
	if !strings.Contains(redacted, "[TG:KEY:") {
		t.Error("redacted content missing key token")
	}
}

func TestRedactCreditCard(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Card: 4111 1111 1111 1111, alt: 5500-0000-0000-0004"
	redacted, summary := r.Redact(content)

	if summary["credit_card"] != 2 {
		t.Errorf("expected 2 credit card redactions, got %d", summary["credit_card"])
	}
	if strings.Contains(redacted, "4111") {
		t.Error("redacted content still contains credit card number")
	}
}

func TestRedactMACAddress(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "MAC: 00:1B:44:11:3A:B7"
	redacted, summary := r.Redact(content)

	if summary["mac_address"] != 1 {
		t.Errorf("expected 1 MAC redaction, got %d", summary["mac_address"])
	}
	if strings.Contains(redacted, "00:1B:44:11:3A:B7") {
		t.Error("redacted content still contains MAC address")
	}
}

func TestRedactPhone(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Call +49 170 1234567 or +1-555-123-4567"
	redacted, summary := r.Redact(content)

	if summary["phone"] != 2 {
		t.Errorf("expected 2 phone redactions, got %d", summary["phone"])
	}
	if strings.Contains(redacted, "170 1234567") {
		t.Error("redacted content still contains phone number")
	}
}

func TestRedactMultiplePatterns(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Server config:\n  IP: 203.0.113.42\n  Admin: admin@myapp.com\n  Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234\n  Key: -----BEGIN OPENSSH PRIVATE KEY-----\n  (key content here)\n  -----END OPENSSH PRIVATE KEY-----"
	redacted, summary := r.Redact(content)

	if summary.Total() < 3 {
		t.Errorf("expected at least 3 redactions, got %d", summary.Total())
	}
	if strings.Contains(redacted, "203.0.113.42") ||
		strings.Contains(redacted, "admin@myapp.com") ||
		strings.Contains(redacted, "ghp_") {
		t.Error("redacted content still contains sensitive data")
	}
}

func TestRestore(t *testing.T) {
	r := New()
	defer r.Clear()

	original := "Server at 203.0.113.42 with admin@example.com"
	redacted, _ := r.Redact(original)

	if strings.Contains(redacted, "203.0.113.42") {
		t.Fatal("redacted content still contains original IP")
	}

	restored := r.Restore(redacted)
	if !strings.Contains(restored, "203.0.113.42") {
		t.Error("restored content missing original IP")
	}
	if !strings.Contains(restored, "admin@example.com") {
		t.Error("restored content missing original email")
	}
}

func TestDeduplication(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "IP 10.0.0.1 appears twice: 10.0.0.1 and 10.0.0.1"
	redacted, summary := r.Redact(content)

	// Should redact 3 occurrences but only create 1 mapping entry
	if summary["ipv4"] != 3 {
		t.Errorf("expected 3 IPv4 matches, got %d", summary["ipv4"])
	}
	if r.MappingCount() != 1 {
		t.Errorf("expected 1 mapping entry (dedup), got %d", r.MappingCount())
	}
	// All occurrences should be the same token
	token := "[TG:IP:1:00000000]"
	count := strings.Count(redacted, token)
	if count != 3 {
		t.Errorf("expected 3 occurrences of same token, got %d", count)
	}
}

func TestDisablePattern(t *testing.T) {
	r := New()
	defer r.Clear()

	if !r.DisablePattern("ipv4") {
		t.Fatal("expected to find and disable ipv4 pattern")
	}

	content := "Server at 203.0.113.42"
	redacted, summary := r.Redact(content)

	if _, ok := summary["ipv4"]; ok {
		t.Error("disabled pattern should not redact")
	}
	if !strings.Contains(redacted, "203.0.113.42") {
		t.Error("disabled pattern should leave content unchanged")
	}
}

func TestEnablePattern(t *testing.T) {
	r := New()
	defer r.Clear()

	// Disable then re-enable
	r.DisablePattern("email")
	r.EnablePattern("email")

	content := "admin@example.com"
	redacted, summary := r.Redact(content)

	if summary["email"] != 1 {
		t.Error("re-enabled pattern should redact")
	}
	if strings.Contains(redacted, "admin@example.com") {
		t.Error("re-enabled pattern should have redacted email")
	}
}

func TestClear(t *testing.T) {
	r := New()

	r.Redact("IP 203.0.113.42")
	if r.MappingCount() == 0 {
		t.Fatal("expected mappings after redact")
	}

	r.Clear()
	if r.MappingCount() != 0 {
		t.Error("expected zero mappings after clear")
	}
}

func TestExtendedPatterns(t *testing.T) {
	r := New().WithPatterns(ExtendedPatterns())
	defer r.Clear()

	// Enable private IP pattern (disabled by default in extended set)
	r.EnablePattern("ipv4_private")
	r.EnablePattern("hostname_internal")
	r.EnablePattern("database_connection")

	content := "Connect to 192.168.1.1 or db.internal.lan or postgres://user:pass@host:5432/db"
	redacted, summary := r.Redact(content)

	if summary["ipv4_private"] == 0 && summary["ipv4"] == 0 {
		t.Error("expected private IP to be redacted")
	}
	if summary["hostname_internal"] != 1 {
		t.Errorf("expected 1 hostname redaction, got %d", summary["hostname_internal"])
	}
	if summary["database_connection"] != 1 {
		t.Errorf("expected 1 DB connection redaction, got %d", summary["database_connection"])
	}
	_ = redacted
}

func TestNoFalsePositiveVersionNumbers(t *testing.T) {
	r := New()
	defer r.Clear()

	// Version numbers should not be redacted as IPs
	content := "Using go version 1.22.2 with node 20.10.0"
	redacted, _ := r.Redact(content)

	// "1.22.2" has 3 segments, not 4 — should not match IPv4
	// "20.10.0" same — should not match
	if strings.Contains(redacted, "[TG:IP:") {
		t.Error("version numbers should not be redacted as IPs")
	}
}

func TestIPv6(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	redacted, summary := r.Redact(content)

	if summary["ipv6"] != 1 {
		t.Errorf("expected 1 IPv6 redaction, got %d", summary["ipv6"])
	}
	if strings.Contains(redacted, "2001:0db8") {
		t.Error("redacted content still contains IPv6 address")
	}
}
