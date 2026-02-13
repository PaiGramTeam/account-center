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
	// TypeCleanExpiredOAuthStates is the periodic task to clean expired OAuth states
	TypeCleanExpiredOAuthStates = "oauth:clean_expired_states"
)

// CleanExpiredOAuthStatesPayload represents the payload
type CleanExpiredOAuthStatesPayload struct{}

// NewCleanExpiredOAuthStatesTask creates a new cleanup task
func NewCleanExpiredOAuthStatesTask() (*asynq.Task, error) {
	payload, err := json.Marshal(CleanExpiredOAuthStatesPayload{})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TypeCleanExpiredOAuthStates, payload), nil
}

// CleanExpiredOAuthStatesHandler deletes expired OAuth state records
type CleanExpiredOAuthStatesHandler struct {
	db *gorm.DB
}

// NewCleanExpiredOAuthStatesHandler creates a new handler
func NewCleanExpiredOAuthStatesHandler(db *gorm.DB) *CleanExpiredOAuthStatesHandler {
	return &CleanExpiredOAuthStatesHandler{db: db}
}

// ProcessTask deletes OAuth states that have expired
func (h *CleanExpiredOAuthStatesHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	log.Println("[CleanExpiredOAuthStates] Starting cleanup...")

	now := time.Now().UTC()

	// Delete all expired states
	result := h.db.Where("expires_at < ?", now).Delete(&model.UserOAuthState{})
	if result.Error != nil {
		return fmt.Errorf("delete expired states: %w", result.Error)
	}

	deleted := result.RowsAffected
	if deleted > 0 {
		log.Printf("[CleanExpiredOAuthStates] Deleted %d expired OAuth states", deleted)
	} else {
		log.Println("[CleanExpiredOAuthStates] No expired states to clean")
	}

	return nil
}
