package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"paigram/internal/model"
)

const (
	// TypeCleanExpiredBotTokens is the periodic task to clean expired bot tokens
	TypeCleanExpiredBotTokens = "bot:clean_expired_tokens"
)

// CleanExpiredBotTokensPayload represents the payload
type CleanExpiredBotTokensPayload struct{}

// NewCleanExpiredBotTokensTask creates a new bot token cleanup task
func NewCleanExpiredBotTokensTask() (*asynq.Task, error) {
	payload, err := json.Marshal(CleanExpiredBotTokensPayload{})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TypeCleanExpiredBotTokens, payload), nil
}

// CleanExpiredBotTokensHandler deletes expired and revoked bot token records
type CleanExpiredBotTokensHandler struct {
	db *gorm.DB
}

// NewCleanExpiredBotTokensHandler creates a new handler
func NewCleanExpiredBotTokensHandler(db *gorm.DB) *CleanExpiredBotTokensHandler {
	return &CleanExpiredBotTokensHandler{db: db}
}

// ProcessTask deletes bot tokens that have expired or been revoked
func (h *CleanExpiredBotTokensHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	log.Println("[CleanExpiredBotTokens] Starting cleanup...")

	now := time.Now().UTC()

	// Delete expired tokens
	expiredResult := h.db.Where("expires_at < ?", now).Delete(&model.BotToken{})
	if expiredResult.Error != nil {
		return fmt.Errorf("delete expired tokens: %w", expiredResult.Error)
	}

	// Delete revoked tokens (older than 7 days to allow for debugging)
	revokedCutoff := now.Add(-7 * 24 * time.Hour)
	revokedResult := h.db.Where("revoked_at IS NOT NULL AND revoked_at < ?", revokedCutoff).Delete(&model.BotToken{})
	if revokedResult.Error != nil {
		return fmt.Errorf("delete revoked tokens: %w", revokedResult.Error)
	}

	totalDeleted := expiredResult.RowsAffected + revokedResult.RowsAffected
	if totalDeleted > 0 {
		log.Printf("[CleanExpiredBotTokens] Deleted %d expired and %d revoked tokens (total: %d)",
			expiredResult.RowsAffected, revokedResult.RowsAffected, totalDeleted)
	} else {
		log.Println("[CleanExpiredBotTokens] No expired or revoked tokens to clean")
	}

	return nil
}
