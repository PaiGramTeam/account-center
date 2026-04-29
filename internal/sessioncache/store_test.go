package sessioncache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// V4 (security): the Redis key used for session tokens MUST NOT embed the raw
// token. A snapshot of Redis (RDB dump, MEMORY usage, slowlog, accidental KEYS
// dump in logs) would otherwise leak every active access/refresh token.
//
// These tests pin the invariant at the key-builder level. We deliberately do
// not stand up a real Redis (or pull in miniredis as a new dependency) for
// what is fundamentally a key-shape contract: the builders are pure string
// functions, so we test them directly.

func TestTokenKey_DoesNotContainRawToken(t *testing.T) {
	store := &RedisStore{prefix: "paigram"}

	const accessToken = "AAA-secret-access-token-do-not-leak"
	const refreshToken = "BBB-secret-refresh-token-do-not-leak"

	accessKey := store.tokenKey(TokenTypeAccess, accessToken)
	refreshKey := store.tokenKey(TokenTypeRefresh, refreshToken)

	if strings.Contains(accessKey, accessToken) {
		t.Fatalf("V4: access token leaked into Redis key: %q contains %q", accessKey, accessToken)
	}
	if strings.Contains(refreshKey, refreshToken) {
		t.Fatalf("V4: refresh token leaked into Redis key: %q contains %q", refreshKey, refreshToken)
	}
}

func TestTokenKey_UsesSHA256HexOfToken(t *testing.T) {
	store := &RedisStore{prefix: "paigram"}

	const token = "AAA-secret-access-token-do-not-leak"
	sum := sha256.Sum256([]byte(token))
	expectedFingerprint := hex.EncodeToString(sum[:])

	got := store.tokenKey(TokenTypeAccess, token)
	if !strings.Contains(got, expectedFingerprint) {
		t.Fatalf("V4: tokenKey should embed the SHA-256 hex of the token; got %q, want it to contain %q", got, expectedFingerprint)
	}
}

func TestTokenKey_DeterministicForSameInput(t *testing.T) {
	// Two independently-constructed RedisStore instances with the same prefix
	// must derive the same key for the same token, otherwise SaveSession ->
	// GetSession lookups would break across handler boundaries.
	a := &RedisStore{prefix: "paigram"}
	b := &RedisStore{prefix: "paigram"}

	const token = "shared-original-token"
	if a.tokenKey(TokenTypeAccess, token) != b.tokenKey(TokenTypeAccess, token) {
		t.Fatalf("V4: tokenKey is non-deterministic for the same token+prefix; lookup will fail")
	}
	if a.revokedKey(TokenTypeRefresh, token) != b.revokedKey(TokenTypeRefresh, token) {
		t.Fatalf("V4: revokedKey is non-deterministic for the same token+prefix; lookup will fail")
	}
}

func TestRevokedKey_DoesNotContainRawToken(t *testing.T) {
	store := &RedisStore{prefix: "paigram"}

	const token = "CCC-secret-revoked-token-do-not-leak"
	got := store.revokedKey(TokenTypeAccess, token)

	if strings.Contains(got, token) {
		t.Fatalf("V4: revoked-marker key leaked the raw token: %q contains %q", got, token)
	}

	sum := sha256.Sum256([]byte(token))
	expected := hex.EncodeToString(sum[:])
	if !strings.Contains(got, expected) {
		t.Fatalf("V4: revokedKey should embed the SHA-256 hex of the token; got %q, want it to contain %q", got, expected)
	}
}

func TestTokenKey_DifferentTokensProduceDifferentKeys(t *testing.T) {
	// Sanity: different inputs must not collide (would happen if hashing was
	// dropped or replaced with a constant).
	store := &RedisStore{prefix: "paigram"}

	if store.tokenKey(TokenTypeAccess, "token-one") == store.tokenKey(TokenTypeAccess, "token-two") {
		t.Fatalf("V4: distinct tokens produced identical keys")
	}
}

// TestHashTokenForKey_EmptyInputProducesDeterministicHash pins the post-review
// behavior of hashTokenForKey on empty input. Earlier the function had an
// `if token == "" { return "" }` short-circuit; that was removed because it
// (a) silently collapsed every empty-token bug to the same key shape
// (paigram:session:access: with empty hex suffix) and (b) hid the regression
// instead of producing a deterministic, distinct key. SHA-256("") is a fixed,
// well-known digest -- it does NOT collide with any non-empty input -- so
// letting the pure transform run is both safer and simpler.
//
// This test pins that contract: empty input goes through the same transform
// as any other input, with the standard empty-bytes SHA-256 hex digest.
func TestHashTokenForKey_EmptyInputProducesDeterministicHash(t *testing.T) {
	const wellKnownEmptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got := hashTokenForKey("")
	if got != wellKnownEmptySHA256Hex {
		t.Fatalf("hashTokenForKey(\"\") = %q, want %q (the well-known SHA-256 of empty input)", got, wellKnownEmptySHA256Hex)
	}

	// Also assert it does NOT alias with any non-empty input that might be
	// confused for "no token" by a future caller bug.
	if got == hashTokenForKey("anything-non-empty") {
		t.Fatalf("hashTokenForKey: empty and non-empty inputs collided")
	}
}
