// Package secsubtle provides constant-time helpers for security-sensitive
// equality checks. Use these helpers instead of the built-in `==` operator
// when comparing secrets, MACs, nonces, tokens, or any value an attacker can
// observe through timing side channels.
package secsubtle

import "crypto/subtle"

// StringEqual reports whether two strings are equal in constant time. The
// comparison still leaks the lengths of the inputs (as does any
// length-defending wrapper around byte comparison), but it does not leak the
// position of the first differing byte.
//
// StringEqual is the canonical entry point for nonce, token, MAC, and similar
// equality checks across the codebase. Prefer it over `subtle.ConstantTimeCompare`
// directly so call sites can be audited via grep.
func StringEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
