package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwksTestServer is a small fixture that exposes a JWKS endpoint backed by
// the provided RSA key under kid "test-kid" and signs tokens with it.
type jwksTestServer struct {
	t          *testing.T
	priv       *rsa.PrivateKey
	pub        *rsa.PrivateKey // alternate (used to forge tokens with a different key)
	server     *httptest.Server
	includeKid bool
}

func newJWKSTestServer(t *testing.T) *jwksTestServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	js := &jwksTestServer{t: t, priv: priv, includeKid: true}
	js.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		keys := []map[string]any{}
		if js.includeKid {
			keys = append(keys, map[string]any{
				"kty": "RSA",
				"kid": "test-kid",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
			})
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"keys": keys}))
	}))
	t.Cleanup(js.server.Close)
	return js
}

func (s *jwksTestServer) signRS256(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(s.priv)
	require.NoError(t, err)
	return signed
}

func defaultClaims(issuer, aud, nonce string, exp time.Time) Claims {
	// IssuedAt is set to "now" (computed relative to the test's wall clock)
	// so the iat freshness check sees a sane value regardless of how far in
	// the future exp is.
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{aud},
			Subject:   "user-123",
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	}
}

func TestVerifier_AcceptsValidlySignedToken(t *testing.T) {
	js := newJWKSTestServer(t)

	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	tok := js.signRS256(t, defaultClaims("https://issuer.test", "client-id", "expected-nonce", time.Now().Add(time.Hour)))

	got, err := v.Verify(context.Background(), tok, "expected-nonce")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "user-123", got.Subject)
	assert.Equal(t, "expected-nonce", got.Nonce)
}

func TestVerifier_RejectsUnsignedToken(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	// Build alg=none token by hand. golang-jwt v5 forbids creating these via
	// SigningMethodNone unless the unsafe sentinel is used; we assemble the
	// raw form ourselves so the parser sees a real "alg":"none" header.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"test-kid"}`))
	payloadJSON, err := json.Marshal(defaultClaims("https://issuer.test", "client-id", "expected-nonce", time.Now().Add(time.Hour)))
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	noneToken := header + "." + payload + "."

	_, err = v.Verify(context.Background(), noneToken, "expected-nonce")
	require.Error(t, err)

	// HMAC-confusion: try HS256 with attacker-chosen key.
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, defaultClaims("https://issuer.test", "client-id", "expected-nonce", time.Now().Add(time.Hour)))
	hsTok.Header["kid"] = "test-kid"
	hsSigned, err := hsTok.SignedString([]byte("attacker-secret"))
	require.NoError(t, err)
	_, err = v.Verify(context.Background(), hsSigned, "expected-nonce")
	require.Error(t, err)
}

func TestVerifier_RejectsTokenSignedByWrongKey(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	// Generate a different key and sign with it. The JWKS server only
	// publishes keys derived from js.priv, so this should fail signature
	// verification (or, if the kid happens to lookup miss, fail with unknown
	// kid).
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, defaultClaims("https://issuer.test", "client-id", "expected-nonce", time.Now().Add(time.Hour)))
	tok.Header["kid"] = "test-kid" // matches the JWKS' kid, but the key bytes differ
	signed, err := tok.SignedString(other)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), signed, "expected-nonce")
	require.Error(t, err)
}

func TestVerifier_RejectsMismatchedNonce(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	tok := js.signRS256(t, defaultClaims("https://issuer.test", "client-id", "wrong-nonce", time.Now().Add(time.Hour)))
	_, err = v.Verify(context.Background(), tok, "expected-nonce")
	require.Error(t, err)
}

func TestVerifier_RejectsEmptyNonceClaimWhenExpected(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	// The token has no `nonce` claim. Caller still expects one. The original
	// ParseUnverified code accepted this — that was the bypass.
	c := defaultClaims("https://issuer.test", "client-id", "", time.Now().Add(time.Hour))
	tok := js.signRS256(t, c)

	_, err = v.Verify(context.Background(), tok, "expected-nonce")
	require.Error(t, err)
}

func TestVerifier_RejectsExpiredToken(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
		Leeway:   time.Second, // tighten leeway so we don't accidentally accept
	})
	require.NoError(t, err)

	tok := js.signRS256(t, defaultClaims("https://issuer.test", "client-id", "expected-nonce", time.Now().Add(-time.Hour)))
	_, err = v.Verify(context.Background(), tok, "expected-nonce")
	require.Error(t, err)
}

func TestVerifier_RejectsWrongIssuerOrAudience(t *testing.T) {
	js := newJWKSTestServer(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://issuer.test",
		Audience: "client-id",
		JWKSURL:  js.server.URL,
	})
	require.NoError(t, err)

	// Wrong issuer
	tok := js.signRS256(t, defaultClaims("https://attacker.example", "client-id", "expected-nonce", time.Now().Add(time.Hour)))
	_, err = v.Verify(context.Background(), tok, "expected-nonce")
	require.Error(t, err)

	// Wrong audience
	tok2 := js.signRS256(t, defaultClaims("https://issuer.test", "other-client", "expected-nonce", time.Now().Add(time.Hour)))
	_, err = v.Verify(context.Background(), tok2, "expected-nonce")
	require.Error(t, err)
}

func TestNewVerifier_RequiresFields(t *testing.T) {
	_, err := NewVerifier(Config{Audience: "x", JWKSURL: "y"})
	assert.Error(t, err)
	_, err = NewVerifier(Config{Issuer: "x", JWKSURL: "y"})
	assert.Error(t, err)
	_, err = NewVerifier(Config{Issuer: "x", Audience: "y"})
	assert.Error(t, err)
}
