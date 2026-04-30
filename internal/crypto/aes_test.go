package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	// Generate a random 32-byte key for testing
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	err = SetEncryptionKey(key)
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "hello world",
		},
		{
			name:      "TOTP secret",
			plaintext: "JBSWY3DPEHPK3PXP",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "long text",
			plaintext: "this is a very long text that should still be encrypted and decrypted correctly without any issues",
		},
		{
			name:      "special characters",
			plaintext: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := Encrypt(tt.plaintext)
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)
			assert.NotEqual(t, tt.plaintext, ciphertext)

			// Verify it's valid base64
			_, err = base64.StdEncoding.DecodeString(ciphertext)
			assert.NoError(t, err)

			// Decrypt
			decrypted, err := Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestEncryptDeterministic(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	err = SetEncryptionKey(key)
	require.NoError(t, err)

	plaintext := "test message"

	// Encrypt same plaintext multiple times
	ciphertext1, err := Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext2, err := Encrypt(plaintext)
	require.NoError(t, err)

	// Ciphertexts should be different (due to random nonce)
	assert.NotEqual(t, ciphertext1, ciphertext2)

	// But both should decrypt to the same plaintext
	decrypted1, err := Decrypt(ciphertext1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted1)

	decrypted2, err := Decrypt(ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

func TestSetEncryptionKey(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 32-byte key",
			key:     make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "invalid 16-byte key",
			key:     make([]byte, 16),
			wantErr: true,
		},
		{
			name:    "invalid 64-byte key",
			key:     make([]byte, 64),
			wantErr: true,
		},
		{
			name:    "invalid empty key",
			key:     []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetEncryptionKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	err = SetEncryptionKey(key)
	require.NoError(t, err)

	tests := []struct {
		name       string
		ciphertext string
		wantErr    bool
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!@#",
			wantErr:    true,
		},
		{
			name:       "too short ciphertext",
			ciphertext: base64.StdEncoding.EncodeToString([]byte("short")),
			wantErr:    true,
		},
		{
			name:       "corrupted ciphertext",
			ciphertext: base64.StdEncoding.EncodeToString(make([]byte, 50)),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.ciphertext)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEncryptWithoutKey(t *testing.T) {
	// Reset encryption key
	encryptionKey = nil

	_, err := Encrypt("test")
	assert.ErrorIs(t, err, ErrKeyNotSet)

	_, err = Decrypt("test")
	assert.ErrorIs(t, err, ErrKeyNotSet)
}

func TestInitEncryption(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string // returns the keyStr arg to pass
		wantErr bool
	}{
		{
			name: "valid 32-byte raw key from arg",
			setup: func(t *testing.T) string {
				// Ensure env fallback is not used.
				t.Setenv("ENCRYPTION_KEY", "")
				return "12345678901234567890123456789012"
			},
			wantErr: false,
		},
		{
			name: "valid base64 key from arg",
			setup: func(t *testing.T) string {
				t.Setenv("ENCRYPTION_KEY", "")
				key := make([]byte, 32)
				_, _ = rand.Read(key)
				return base64.StdEncoding.EncodeToString(key)
			},
			wantErr: false,
		},
		{
			name: "empty arg falls back to ENCRYPTION_KEY env",
			setup: func(t *testing.T) string {
				t.Setenv("ENCRYPTION_KEY", "12345678901234567890123456789012")
				return ""
			},
			wantErr: false,
		},
		{
			name: "empty arg and empty env",
			setup: func(t *testing.T) string {
				t.Setenv("ENCRYPTION_KEY", "")
				return ""
			},
			wantErr: true,
		},
		{
			name: "invalid key length from arg",
			setup: func(t *testing.T) string {
				t.Setenv("ENCRYPTION_KEY", "")
				return "tooshort"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset encryption key
			encryptionKey = nil

			keyArg := ""
			if tt.setup != nil {
				keyArg = tt.setup(t)
			}
			err := InitEncryption(keyArg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encryptionKey)
				assert.Len(t, encryptionKey, 32)
			}
		})
	}
}
