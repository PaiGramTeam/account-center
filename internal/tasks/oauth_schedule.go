package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
)

const (
	// TypeScheduleOAuthRefresh is the periodic task to find expiring tokens
	TypeScheduleOAuthRefresh = "oauth:schedule_refresh"
)

// ScheduleOAuthRefreshPayload represents the payload for scheduling task
type ScheduleOAuthRefreshPayload struct{}

// NewScheduleOAuthRefreshTask creates a new scheduling task
func NewScheduleOAuthRefreshTask() (*asynq.Task, error) {
	payload, err := json.Marshal(ScheduleOAuthRefreshPayload{})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TypeScheduleOAuthRefresh, payload), nil
}

// ScheduleOAuthRefreshHandler finds expiring tokens and schedules refresh tasks
type ScheduleOAuthRefreshHandler struct {
	db     *gorm.DB
	cfg    *config.Config
	client *asynq.Client
}

// NewScheduleOAuthRefreshHandler creates a new scheduler handler
func NewScheduleOAuthRefreshHandler(db *gorm.DB, cfg *config.Config, client *asynq.Client) *ScheduleOAuthRefreshHandler {
	return &ScheduleOAuthRefreshHandler{
		db:     db,
		cfg:    cfg,
		client: client,
	}
}

// ProcessTask finds expiring OAuth tokens and enqueues refresh tasks
func (h *ScheduleOAuthRefreshHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	log.Println("[ScheduleOAuthRefresh] Starting to check for expiring tokens...")

	// Find credentials with tokens expiring in the next 24 hours
	threshold := time.Now().UTC().Add(24 * time.Hour)
	now := time.Now().UTC()

	var credentials []model.UserCredential
	err := h.db.Where(
		"provider IN (?) AND token_expiry IS NOT NULL AND token_expiry > ? AND token_expiry < ?",
		h.cfg.Auth.AllowedOAuthProviders,
		now,       // Not already expired
		threshold, // Expiring soon
	).Find(&credentials).Error

	if err != nil {
		return fmt.Errorf("query credentials: %w", err)
	}

	if len(credentials) == 0 {
		log.Println("[ScheduleOAuthRefresh] No tokens need refreshing")
		return nil
	}

	log.Printf("[ScheduleOAuthRefresh] Found %d credentials to refresh", len(credentials))

	// Enqueue refresh tasks for each credential
	enqueued := 0
	for _, cred := range credentials {
		// Create refresh task
		task, err := NewRefreshOAuthTokenTask(cred.ID, cred.Provider)
		if err != nil {
			log.Printf("[ScheduleOAuthRefresh] Failed to create task for credential %d: %v", cred.ID, err)
			continue
		}

		// Enqueue with delay based on how soon it expires
		timeUntilExpiry := cred.TokenExpiry.Time.Sub(now)

		var opts []asynq.Option
		if timeUntilExpiry > 12*time.Hour {
			// If more than 12 hours, schedule for 12 hours before expiry
			processAt := cred.TokenExpiry.Time.Add(-12 * time.Hour)
			opts = append(opts, asynq.ProcessAt(processAt))
		}
		// If less than 12 hours, process immediately (default)

		info, err := h.client.Enqueue(task, opts...)
		if err != nil {
			log.Printf("[ScheduleOAuthRefresh] Failed to enqueue task for credential %d: %v", cred.ID, err)
			continue
		}

		log.Printf("[ScheduleOAuthRefresh] Enqueued refresh task for user_id=%d, provider=%s, task_id=%s",
			cred.UserID, cred.Provider, info.ID)
		enqueued++
	}

	log.Printf("[ScheduleOAuthRefresh] Successfully enqueued %d/%d refresh tasks", enqueued, len(credentials))
	return nil
}
