package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultTokenByteLength = 32
	// DefaultBcryptCost is the fallback bcrypt cost if not configured
	// OWASP recommends minimum 12 (takes ~300ms on modern hardware)
	DefaultBcryptCost = 12
)

func randomToken(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = defaultTokenByteLength
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	return strings.TrimRight(token, "="), nil
}

// hashPassword creates a bcrypt hash of the password
// cost parameter should be between 10-14 (default: 12)
func hashPassword(password string, cost int) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password cannot be empty")
	}
	// Validate and sanitize cost
	if cost < 10 {
		cost = DefaultBcryptCost
	}
	if cost > 14 {
		cost = 14 // Cap at 14 to prevent DoS attacks
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func comparePassword(hash string, password string) error {
	if hash == "" {
		return errors.New("empty password hash")
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// hashToken creates a SHA-256 hash of a token for secure storage
func hashToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// getBcryptCost returns the configured bcrypt cost from Handler
func (h *Handler) getBcryptCost() int {
	cost := h.securityCfg.BcryptCost
	if cost < 10 {
		return DefaultBcryptCost
	}
	if cost > 14 {
		return 14
	}
	return cost
}

// generatePKCE generates a PKCE code verifier and challenge
// RFC 7636: Proof Key for Code Exchange
// Returns: (codeVerifier, codeChallenge, error)
func generatePKCE() (string, string, error) {
	// Generate code verifier (43-128 characters, URL-safe base64)
	verifierBytes := make([]byte, 32) // 32 bytes = 43 chars in base64
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code challenge (SHA-256 hash of verifier, base64url encoded)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}
