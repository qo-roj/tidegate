package redact

// luhn.go — check-digit validation for structured identifiers.
//
// A shape-only regex cannot tell a credit card number from an order ID: both
// are 13–16 digit runs. Every real PAN carries a Luhn check digit, so a match
// that fails the checksum is an identifier-shaped number, not a card, and
// passes through untouched. This kills the false-positive class (order IDs,
// invoice numbers, ticket references) without weakening redaction: no real
// PAN fails Luhn, so no true positive is ever dropped.
//
// Methodology note: the check-digit approach mirrors Penteos's detector
// design (penteos.com, AGPL-3.0) — validate the format's own checksum before
// treating a number as sensitive. The Luhn algorithm itself is public-domain
// math (ANSI X4.13, ISO/IEC 7812-1); this implementation is original.

// luhnValid reports whether the digit run inside s passes the Luhn checksum.
// Non-digit characters (spaces, dashes) are ignored, matching how the
// credit_card pattern captures separated groups ("4111 1111 1111 1111").
// s must contain 13–19 digits — the range of real PAN lengths — so a shorter
// or longer digit fragment can never be validated by accident.
func luhnValid(s string) bool {
	var digits []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
