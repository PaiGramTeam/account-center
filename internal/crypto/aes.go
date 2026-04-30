package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	// ErrInvalidKey is returned when the encryption key is invalid
	ErrInvalidKey = errors.New("encryption key must be 32 bytes (AES-256)")
	// ErrInvalidCiphertext is returned when the ciphertext is too short or malformed
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	// ErrKeyNotSet is returned when encryption key is not configured
	ErrKeyNotSet = errors.New("encryption key not configured (set security.encryption_key in config or PAI_SECURITY_ENCRYPTION_KEY / ENCRYPTION_KEY environment variable)")
)

// encryptionKey holds the global encryption key loaded at startup.
var encryptionKey []byte

// InitEncryption initializes the global encryption key.
//
// keyStr is the configured key as either:
//   - a raw 32-byte ASCII string, or
//   - a base64-encoded 32-byte key (auto-detected when standard-base64 padding/special
//     characters are present, or when the decoded length is exactly 32 bytes).
//
// If keyStr is empty, InitEncryption falls back to the legacy ENCRYPTION_KEY
// environment variable for backwards compatibility with deployments that
// predate the config-driven flow. Operators should migrate to either
// `security.encryption_key` in config.yaml or PAI_SECURITY_ENCRYPTION_KEY.
func InitEncryption(keyStr string) error {
	keyStr = strings.TrimSpace(keyStr)

	// Backwards-compatible fallback to the legacy bare env var. Kept
	// intentionally so existing CI / local setups keep working while
	// teams migrate to the config-driven approach.
	if keyStr == "" {
		keyStr = strings.TrimSpace(os.Getenv("ENCRYPTION_KEY"))
	}
	if keyStr == "" {
		return ErrKeyNotSet
	}

	// Try base64 first when the input looks base64-shaped. We only
	// accept the result if it decodes to exactly 32 bytes; otherwise
	// fall through to the raw-string branch so a 32-char ASCII key
	// containing '+', '/', or '=' still works.
	if strings.ContainsAny(keyStr, "+/=") {
		if decoded, err := base64.StdEncoding.DecodeString(keyStr); err == nil && len(decoded) == 32 {
			encryptionKey = decoded
			return nil
		}
	}

	if len(keyStr) != 32 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(keyStr))
	}

	encryptionKey = []byte(keyStr)
	return nil
}

// GetEncryptionKey returns the current encryption key
// For testing purposes only
func GetEncryptionKey() []byte {
	return encryptionKey
}

// SetEncryptionKey sets a custom encryption key
// For testing purposes only
func SetEncryptionKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}
	encryptionKey = key
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns base64-encoded ciphertext with nonce prepended
func Encrypt(plaintext string) (string, error) {
	if encryptionKey == nil {
		return "", ErrKeyNotSet
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt and append to nonce
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM
func Decrypt(ciphertextB64 string) (string, error) {
	if encryptionKey == nil {
		return "", ErrKeyNotSet
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
