// Package oidc implements OpenID Connect ID-token verification for OAuth
// providers other than Telegram (whose flow lives in the auth handler for
// historical reasons).
//
// Design goals:
//
//   - Fail closed. If the verifier is configured for an unknown provider with
//     no Issuer/JWKSURL, every Verify call returns an error. There is no
//     "ParseUnverified" fallback anywhere in this package.
//   - Strict claim validation: signature, issuer, audience, expiry, and nonce.
//   - Constant-time nonce comparison via internal/utils/secsubtle.
//   - Cache JWKS per (issuer, jwks_uri) with a small TTL plus refresh-on-unknown-kid
//     so key rotations on the provider side are picked up within a single
//     verification round-trip.
//
// This package depends only on the Go standard library and golang-jwt/jwt/v5.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"paigram/internal/utils/secsubtle"
)

// Claims is the subset of OIDC ID-token claims the auth handler consumes.
// Provider-specific extensions can be added here without touching callers.
type Claims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

// Config configures a single OIDC verifier instance. Tests may override
// Now and Clock-leeway; production callers should leave them at zero.
type Config struct {
	// Issuer is the expected `iss` claim. Required.
	Issuer string
	// Audience is the expected `aud` claim entry (typically the OAuth ClientID). Required.
	Audience string
	// JWKSURL is fetched lazily and cached. Required.
	JWKSURL string
	// HTTPTimeout bounds JWKS HTTP fetches. Defaults to 10s when zero.
	HTTPTimeout time.Duration
	// JWKSCacheTTL controls how often a successful JWKS fetch is reused.
	// Defaults to 10 minutes when zero. Independent of refresh-on-unknown-kid.
	JWKSCacheTTL time.Duration
	// Leeway is allowed clock skew for exp/nbf/iat checks. Defaults to 1 minute.
	Leeway time.Duration
	// Now overrides the clock for tests.
	Now func() time.Time
}

// Verifier validates ID tokens for a single provider. It is safe for
// concurrent use after construction.
type Verifier struct {
	cfg  Config
	keys *jwksCache
}

// NewVerifier constructs a Verifier from cfg. It returns an error if any
// required field is missing — callers MUST treat a missing OIDC config as a
// hard failure rather than skipping verification.
func NewVerifier(cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("oidc: Issuer is required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("oidc: Audience is required")
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, errors.New("oidc: JWKSURL is required")
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = 10 * time.Minute
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{
		cfg:  cfg,
		keys: newJWKSCache(cfg.JWKSURL, cfg.JWKSCacheTTL, cfg.HTTPTimeout),
	}, nil
}

// Verify parses and verifies the supplied id_token. It returns the validated
// claims on success.
//
// Validation steps, in order:
//  1. Reject any token whose header `alg` is not in the allowed list (RS256,
//     RS384, RS512). This blocks `alg: none` and HMAC-confusion attacks.
//  2. Resolve the signing key by `kid` from cached JWKS (refresh-on-miss).
//  3. Verify the cryptographic signature.
//  4. Verify `iss` matches Config.Issuer.
//  5. Verify `aud` contains Config.Audience.
//  6. Verify `exp`, `iat`, `nbf` against Config.Now() with Config.Leeway.
//  7. If expectedNonce is non-empty, verify `nonce` claim equals it using a
//     constant-time comparison. An empty `nonce` claim is rejected — that is
//     the bypass the original ParseUnverified code allowed.
//
// Verify returns a wrapped error describing the failed step. Callers should
// log the error but should not propagate it to end users (it can leak
// signing-key/issuer details that aid attackers).
func (v *Verifier) Verify(ctx context.Context, idToken, expectedNonce string) (*Claims, error) {
	if v == nil {
		return nil, errors.New("oidc: nil verifier")
	}
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("oidc: empty id_token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		// We do our own time validation against Config.Now so tests can stub the clock.
		jwt.WithoutClaimsValidation(),
	)

	claims := &Claims{}
	tok, err := parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("oidc: missing kid in token header")
		}
		return v.keys.lookupKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: signature verification failed: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("oidc: token reported invalid")
	}

	now := v.cfg.Now()
	if err := v.validateClaims(claims, expectedNonce, now); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateClaims runs the iss/aud/time/nonce checks. Split out for clarity
// and to keep Verify within the per-function size budget.
func (v *Verifier) validateClaims(claims *Claims, expectedNonce string, now time.Time) error {
	if claims.Issuer == "" || claims.Issuer != v.cfg.Issuer {
		return fmt.Errorf("oidc: issuer mismatch: got %q want %q", claims.Issuer, v.cfg.Issuer)
	}

	if !audienceContains(claims.Audience, v.cfg.Audience) {
		return fmt.Errorf("oidc: audience mismatch: %v does not contain %q", claims.Audience, v.cfg.Audience)
	}

	if claims.ExpiresAt == nil {
		return errors.New("oidc: missing exp claim")
	}
	if claims.ExpiresAt.Time.Before(now.Add(-v.cfg.Leeway)) {
		return fmt.Errorf("oidc: token expired at %s (now=%s)", claims.ExpiresAt.Time, now)
	}

	if claims.IssuedAt != nil && claims.IssuedAt.Time.After(now.Add(v.cfg.Leeway)) {
		return fmt.Errorf("oidc: iat is in the future: %s (now=%s)", claims.IssuedAt.Time, now)
	}
	if claims.NotBefore != nil && claims.NotBefore.Time.After(now.Add(v.cfg.Leeway)) {
		return fmt.Errorf("oidc: nbf is in the future: %s (now=%s)", claims.NotBefore.Time, now)
	}

	// Strict nonce validation: when caller has an expectedNonce, the token MUST
	// carry an equal nonce. An empty `nonce` claim is rejected — that was the
	// original ParseUnverified bypass: an attacker could simply omit the nonce.
	if expectedNonce != "" {
		if claims.Nonce == "" {
			return errors.New("oidc: missing nonce claim while a nonce was expected")
		}
		if !secsubtle.StringEqual(claims.Nonce, expectedNonce) {
			return errors.New("oidc: nonce mismatch")
		}
	}

	return nil
}

func audienceContains(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
