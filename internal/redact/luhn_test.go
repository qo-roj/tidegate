package redact

import (
	"strings"
	"testing"
)

func TestLuhnValid(t *testing.T) {
	valid := []string{
		"4111111111111111",    // Visa test PAN
		"4111 1111 1111 1111", // separated
		"4111-1111-1111-1111", // dashed
		"5500000000000004",    // Mastercard test PAN
		"5500-0000-0000-0004", // dashed MC
		"378282246310005",     // Amex test PAN (15 digits)
		"3782 822463 10005",   // Amex with spaces
		"4222222222222",       // 13-digit Visa test PAN
		"6011111111111117",    // Discover test PAN
		"3530111333300000",    // JCB test PAN
	}
	for _, s := range valid {
		if !luhnValid(s) {
			t.Errorf("luhnValid(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"4111111111111112",     // check digit off by one
		"1234567890123456",     // 16-digit order ID shape
		"1234567890123",        // 13-digit invoice shape
		"9999999999999994",     // fails Luhn (all-9 body + 4 check)
		"",                     // empty
		"4111 1111",            // too few digits
		"12345678901234567890", // too many digits (>19)
	}
	for _, s := range invalid {
		if luhnValid(s) {
			t.Errorf("luhnValid(%q) = true, want false", s)
		}
	}
}

// TestRedactCreditCardLuhnFP ensures a 13–16 digit identifier-shaped number
// (order ID, invoice number) passes through untouched now that the
// credit_card pattern carries a Luhn validator. This is the false-positive
// class the v0.8.0 Validate hook exists to kill.
func TestRedactCreditCardLuhnFP(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "order 1234567890123456 shipped, invoice 1000000001234 paid"
	redacted, summary := r.Redact(content)

	if summary["credit_card"] != 0 {
		t.Errorf("expected 0 credit_card redactions for non-Luhn digit runs, got %d", summary["credit_card"])
	}
	for _, raw := range []string{"1234567890123456", "1000000001234"} {
		if !strings.Contains(redacted, raw) {
			t.Errorf("non-Luhn digit run %q was redacted: %q", raw, redacted)
		}
	}
	if strings.Contains(redacted, "[TG:CC:") {
		t.Errorf("unexpected CC token in output: %q", redacted)
	}
}

// TestRedactCreditCardLuhnTruePositive: valid PANs still redact in every
// separated shape the pattern allows, and distinct PANs keep distinct tokens.
func TestRedactCreditCardLuhnTruePositive(t *testing.T) {
	r := New()
	defer r.Clear()

	content := "Card: 4111 1111 1111 1111, alt: 5500-0000-0000-0004, amex: 3782 822463 10005"
	redacted, summary := r.Redact(content)

	if summary["credit_card"] != 3 {
		t.Errorf("expected 3 credit_card redactions, got %d", summary["credit_card"])
	}
	tokens := strings.Count(redacted, "[TG:CC:")
	if tokens != 3 {
		t.Errorf("expected 3 distinct CC tokens, got %d in %q", tokens, redacted)
	}
	for _, pan := range []string{"4111 1111 1111 1111", "5500-0000-0000-0004", "3782 822463 10005"} {
		if strings.Contains(redacted, pan) {
			t.Errorf("Luhn-valid PAN %q leaked: %q", pan, redacted)
		}
	}
}
