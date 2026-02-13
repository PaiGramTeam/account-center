package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/auth"
	"paigram/internal/model"
)

const (
	// TypeRefreshOAuthToken is the task type for refreshing OAuth tokens
	TypeRefreshOAuthToken = "oauth:refresh_token"
)

// RefreshOAuthTokenPayload represents the payload for OAuth token refresh task
type RefreshOAuthTokenPayload struct {
	CredentialID uint64 `json:"credential_id"`
	Provider     string `json:"provider"`
}

// NewRefreshOAuthTokenTask creates a new OAuth token refresh task
func NewRefreshOAuthTokenTask(credentialID uint64, provider string) (*asynq.Task, error) {
	payload, err := json.Marshal(RefreshOAuthTokenPayload{
		CredentialID: credentialID,
		Provider:     provider,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	// Task options: retry up to 3 times with exponential backoff
	return asynq.NewTask(TypeRefreshOAuthToken, payload,
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Second),
	), nil
}

// RefreshOAuthTokenHandler handles OAuth token refresh tasks
type RefreshOAuthTokenHandler struct {
	db      *gorm.DB
	cfg     *config.Config
	handler *auth.Handler
}

// NewRefreshOAuthTokenHandler creates a new handler
func NewRefreshOAuthTokenHandler(db *gorm.DB, cfg *config.Config, handler *auth.Handler) *RefreshOAuthTokenHandler {
	return &RefreshOAuthTokenHandler{
		db:      db,
		cfg:     cfg,
		handler: handler,
	}
}

// ProcessTask processes the OAuth token refresh task
func (h *RefreshOAuthTokenHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	var payload RefreshOAuthTokenPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Fetch credential from database
	var credential model.UserCredential
	if err := h.db.First(&credential, payload.CredentialID).Error; err != nil {
		return fmt.Errorf("fetch credential: %w", err)
	}

	// Get provider config
	providerCfg, ok := h.cfg.Auth.OAuthProviders[payload.Provider]
	if !ok {
		return fmt.Errorf("provider config not found: %s", payload.Provider)
	}

	// Refresh the token
	if err := h.handler.RefreshOAuthTokenPublic(ctx, &credential, providerCfg); err != nil {
		return fmt.Errorf("refresh token failed: %w", err)
	}

	return nil
}
