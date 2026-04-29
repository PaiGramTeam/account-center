package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

// TestHandlerVerifyIDToken_NonTelegramUsesStrictOIDCVerifier exercises the
// V3 fix end-to-end at the handler boundary: a Google-style id_token must be
// signature-verified, not parsed unverified. This catches regressions where
// somebody re-introduces a ParseUnverified fallback.
func TestHandlerVerifyIDToken_NonTelegramUsesStrictOIDCVerifier(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "google-test-kid",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	defer jwks.Close()

	providerCfg := config.OAuthProviderConfig{
		ClientID: "google-client-id",
		Issuer:   "https://issuer.example",
		JWKSURL:  jwks.URL,
	}

	h := &Handler{oidcVerifiers: newOIDCVerifierCache()}

	now := time.Now()
	makeToken := func(claims jwt.Claims, kid string, key *rsa.PrivateKey) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		return signed
	}

	t.Run("accepts validly signed token", func(t *testing.T) {
		good := makeToken(oidcIDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://issuer.example",
				Audience:  jwt.ClaimStrings{"google-client-id"},
				Subject:   "google-user-1",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
			Nonce: "expected-nonce",
		}, "google-test-kid", priv)
		claims, err := h.verifyIDToken(context.Background(), "google", good, providerCfg, "expected-nonce")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "google-user-1", claims.Subject)
	})

	t.Run("rejects token with missing nonce when expected", func(t *testing.T) {
		// Original ParseUnverified bypass: attacker omits nonce claim and
		// the verifier accepts. The new strict verifier MUST reject.
		nonceless := makeToken(oidcIDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://issuer.example",
				Audience:  jwt.ClaimStrings{"google-client-id"},
				Subject:   "google-user-2",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}, "google-test-kid", priv)
		_, err := h.verifyIDToken(context.Background(), "google", nonceless, providerCfg, "expected-nonce")
		require.Error(t, err)
	})

	t.Run("rejects token signed by wrong key", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		bad := makeToken(oidcIDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://issuer.example",
				Audience:  jwt.ClaimStrings{"google-client-id"},
				Subject:   "google-user-3",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
			Nonce: "expected-nonce",
		}, "google-test-kid", other)
		_, err = h.verifyIDToken(context.Background(), "google", bad, providerCfg, "expected-nonce")
		require.Error(t, err)
	})

	t.Run("fails closed when provider lacks issuer/jwks/audience", func(t *testing.T) {
		// Drop Issuer + JWKSURL. There are no defaults registered for
		// "custom" so the verifier cache MUST refuse to build a verifier.
		empty := config.OAuthProviderConfig{ClientID: "any"}
		good := makeToken(oidcIDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://issuer.example",
				Audience:  jwt.ClaimStrings{"any"},
				Subject:   "x",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
			Nonce: "n",
		}, "google-test-kid", priv)
		_, err := h.verifyIDToken(context.Background(), "custom", good, empty, "n")
		require.Error(t, err)
	})
}

func TestHandlerVerifyIDToken_EmptyTokenReturnsNilWithNoError(t *testing.T) {
	// Some providers (e.g. GitHub legacy) do not return id_token. The handler
	// signals "no claims available" via (nil, nil). Downstream code must not
	// dereference a nil claim — that is exercised by the existing
	// fetchUserInfo tests.
	h := &Handler{oidcVerifiers: newOIDCVerifierCache()}
	claims, err := h.verifyIDToken(context.Background(), "github", "", config.OAuthProviderConfig{}, "")
	require.NoError(t, err)
	assert.Nil(t, claims)
}

// TestVerifyTelegramIDToken_RejectsEmptyNonceClaimWhenExpected is a
// regression guard for Critical #2 of the C2 review.
//
// Before the fix, verifyTelegramIDToken's nonce check was:
//
//	if expectedNonce != "" && claims.Nonce != "" && !secsubtle.StringEqual(...)
//
// The middle conjunct made an absent nonce claim silently pass — i.e. a
// Telegram id_token with no `nonce` claim was accepted as valid even when
// the server expected a specific nonce. This is the exact bypass V3 closes
// for non-Telegram providers; allowing it on the Telegram path defeats the
// hardening. The fix mirrors the strict policy from oidc.Verifier.
func TestVerifyTelegramIDToken_RejectsEmptyNonceClaimWhenExpected(t *testing.T) {
	// Wire up a fake Telegram JWKS server signed by a fresh RSA key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	originalJWKSURL := telegramOIDCJWKSURL
	originalIssuer := telegramOIDCIssuer
	t.Cleanup(func() {
		telegramOIDCJWKSURL = originalJWKSURL
		telegramOIDCIssuer = originalIssuer
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	defer server.Close()

	telegramOIDCJWKSURL = server.URL
	telegramOIDCIssuer = "https://issuer.example"

	// Construct a properly-signed Telegram id_token that DOES NOT carry a
	// nonce claim (i.e. claims.Nonce == "" after parsing).
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, oidcIDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    telegramOIDCIssuer,
			Subject:   "telegram-user-no-nonce",
			Audience:  jwt.ClaimStrings{"123456789"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		// Nonce intentionally omitted.
	})
	tok.Header["kid"] = "test-kid"
	idToken, err := tok.SignedString(privateKey)
	require.NoError(t, err)

	// Server expected a specific nonce. The strict policy MUST refuse a
	// token that omits the nonce claim — accepting it would let an attacker
	// replay an id_token across sessions.
	_, err = verifyTelegramIDToken(context.Background(), idToken, "123456789", "expected-nonce-abc123")
	require.Error(t, err, "telegram id_token with no nonce claim must be rejected when a nonce was expected")
	assert.Contains(t, strings.ToLower(err.Error()), "nonce", "error should reference the nonce check; got: %v", err)
}

// TestVerifyTelegramIDToken_AcceptsMatchingNonce is a positive control:
// when the token carries the expected nonce, verification succeeds. This
// ensures the strict-nonce fix did not over-correct into rejecting valid
// tokens.
func TestVerifyTelegramIDToken_AcceptsMatchingNonce(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	originalJWKSURL := telegramOIDCJWKSURL
	originalIssuer := telegramOIDCIssuer
	t.Cleanup(func() {
		telegramOIDCJWKSURL = originalJWKSURL
		telegramOIDCIssuer = originalIssuer
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-kid",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	defer server.Close()

	telegramOIDCJWKSURL = server.URL
	telegramOIDCIssuer = "https://issuer.example"

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, oidcIDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    telegramOIDCIssuer,
			Subject:   "telegram-user-with-nonce",
			Audience:  jwt.ClaimStrings{"123456789"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce: "expected-nonce-abc123",
	})
	tok.Header["kid"] = "test-kid"
	idToken, err := tok.SignedString(privateKey)
	require.NoError(t, err)

	claims, err := verifyTelegramIDToken(context.Background(), idToken, "123456789", "expected-nonce-abc123")
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "telegram-user-with-nonce", claims.Subject)
}
