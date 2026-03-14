package auth

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelegramAuthCheckerCreateDataCheckString(t *testing.T) {
	checker := NewTelegramAuthChecker("test-bot-token")
	data := &TelegramAuthData{
		ID:        123456789,
		FirstName: "John",
		LastName:  "Doe",
		Username:  "johndoe",
		PhotoURL:  "https://t.me/i/userpic/320/johndoe.jpg",
		AuthDate:  1700000000,
	}

	assert.Equal(
		t,
		"auth_date=1700000000\nfirst_name=John\nid=123456789\nlast_name=Doe\nphoto_url=https://t.me/i/userpic/320/johndoe.jpg\nusername=johndoe",
		checker.createDataCheckString(data),
	)
}

func TestTelegramAuthCheckerVerifyTelegramAuth(t *testing.T) {
	checker := NewTelegramAuthChecker("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
	data := &TelegramAuthData{
		ID:        987654321,
		FirstName: "Jane",
		LastName:  "Doe",
		Username:  "janedoe",
		PhotoURL:  "https://t.me/i/userpic/320/janedoe.jpg",
		AuthDate:  time.Now().Unix(),
	}

	secretKey := checker.calculateSecretKey()
	data.Hash = hex.EncodeToString(checker.calculateHash(checker.createDataCheckString(data), secretKey))

	require.NoError(t, checker.VerifyTelegramAuth(data))
}

func TestTelegramAuthCheckerVerifyTelegramAuthRejectsExpiredData(t *testing.T) {
	checker := NewTelegramAuthChecker("test-bot-token")
	data := &TelegramAuthData{
		ID:        987654321,
		FirstName: "Jane",
		AuthDate:  time.Now().Add(-25 * time.Hour).Unix(),
	}

	secretKey := checker.calculateSecretKey()
	data.Hash = hex.EncodeToString(checker.calculateHash(checker.createDataCheckString(data), secretKey))

	err := checker.VerifyTelegramAuth(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestTelegramAuthCheckerVerifyTelegramAuthRejectsFutureTimestamp(t *testing.T) {
	checker := NewTelegramAuthChecker("test-bot-token")
	data := &TelegramAuthData{
		ID:        987654321,
		FirstName: "Jane",
		AuthDate:  time.Now().Add(time.Minute).Unix(),
	}

	secretKey := checker.calculateSecretKey()
	data.Hash = hex.EncodeToString(checker.calculateHash(checker.createDataCheckString(data), secretKey))

	err := checker.VerifyTelegramAuth(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestTelegramAuthCheckerVerifyTelegramAuthRejectsInvalidHash(t *testing.T) {
	checker := NewTelegramAuthChecker("test-bot-token")
	data := &TelegramAuthData{
		ID:        987654321,
		FirstName: "Jane",
		AuthDate:  time.Now().Unix(),
		Hash:      "not-a-valid-hash",
	}

	err := checker.VerifyTelegramAuth(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hash encoding")
}

func TestTelegramAuthCheckerVerifyTelegramAuthRejectsMismatchedHash(t *testing.T) {
	checker := NewTelegramAuthChecker("test-bot-token")
	data := &TelegramAuthData{
		ID:        987654321,
		FirstName: "Jane",
		AuthDate:  time.Now().Unix(),
		Hash:      hex.EncodeToString([]byte("wrong hash wrong hash wrong hash!!"))[:64],
	}

	err := checker.VerifyTelegramAuth(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hash")
}
