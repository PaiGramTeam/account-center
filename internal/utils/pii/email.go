// Package pii provides helpers for handling personally-identifiable
// information in places where it must not be logged in plaintext.
//
// Use these helpers for log fields, audit messages, and any other diagnostic
// output. Storage and authentication paths must continue to use the original
// values; only redact at the moment of emission.
package pii

import "strings"

// MaskEmail returns a partially-redacted form of s suitable for logs and
// audit trails. The returned value preserves the domain part so operators
// can still reason about where messages went, while hiding the local-part
// from accidental exposure (e.g. log shipping, screenshots, error reports).
//
// Behavior:
//   - "" returns "".
//   - input without "@" is returned unchanged (it is not an email; do not invent one).
//   - single-character local part returns "*@<domain>".
//   - multi-character local part returns "<first>***@<domain>" where "***" is a
//     fixed-width sentinel (not the original length) so we do not leak the
//     local-part length to log readers.
//   - inputs with multiple "@" characters are masked at the LAST "@" (Postel's
//     law for malformed inputs); this keeps the visible domain matching what
//     the SMTP layer would actually have routed to.
//
// MaskEmail does not validate that the input is a syntactically valid email;
// callers should validate before storing, not before logging.
func MaskEmail(s string) string {
	if s == "" {
		return ""
	}
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s
	}
	local := s[:at]
	domain := s[at:] // includes the "@"
	if local == "" {
		return "*" + domain
	}
	if len(local) == 1 {
		return "*" + domain
	}
	// Show only the first character; mask the rest with a fixed-width sentinel
	// so we don't reveal local-part length.
	return string(local[0]) + "***" + domain
}
