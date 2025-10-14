package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

func (h *Handler) issueSession(tx *gorm.DB, userID uint64, clientIP, userAgent string) (*model.UserSession, error) {
	accessToken, err := randomToken(48)
	if err != nil {
		return nil, err
	}
	refreshToken, err := randomToken(64)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	accessTTL := time.Duration(h.cfg.AccessTokenTTLSeconds) * time.Second
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	refreshTTL := time.Duration(h.cfg.RefreshTokenTTLSeconds) * time.Second
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}

	session := &model.UserSession{
		UserID:        userID,
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AccessExpiry:  now.Add(accessTTL),
		RefreshExpiry: now.Add(refreshTTL),
		UserAgent:     userAgent,
		ClientIP:      clientIP,
	}

	if err := tx.Create(session).Error; err != nil {
		return nil, err
	}

	h.cacheStoreSession(session)

	if h.cfg.MaxConcurrentSessionsPerUser > 0 {
		var sessions []model.UserSession
		if err := tx.Where("user_id = ? AND revoked_at IS NULL AND refresh_expiry > ?", userID, now).
			Order("created_at ASC").
			Find(&sessions).Error; err != nil {
			return nil, err
		}

		for len(sessions) > h.cfg.MaxConcurrentSessionsPerUser {
			oldest := sessions[0]
			if err := tx.Model(&model.UserSession{}).
				Where("id = ?", oldest.ID).
				Updates(map[string]interface{}{
					"revoked_at":     now,
					"revoked_reason": "session_limit_exceeded",
				}).Error; err != nil {
				return nil, err
			}
			h.cacheRevokeSessionTokens(&oldest)
			sessions = sessions[1:]
		}
	}

	return session, nil
}

func (h *Handler) revokeSession(tx *gorm.DB, session *model.UserSession, reason string) error {
	if session == nil {
		return nil
	}
	now := time.Now().UTC()
	update := map[string]interface{}{
		"revoked_at":     now,
		"revoked_reason": reason,
	}
	if err := tx.Model(&model.UserSession{}).
		Where("id = ? AND revoked_at IS NULL", session.ID).
		Updates(update).Error; err != nil {
		return err
	}
	return nil
}

func (h *Handler) recordLoginAudit(tx *gorm.DB, audit model.LoginAudit) error {
	return tx.Create(&audit).Error
}

func (h *Handler) cacheStoreSession(session *model.UserSession) {
	if session == nil {
		return
	}
	ctx := context.Background()
	if err := h.sessionCache.SaveSession(ctx, session); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to cache session tokens: %v", err)
	}
}

func (h *Handler) cacheRevokeSessionTokens(session *model.UserSession) {
	if session == nil {
		return
	}
	ctx := context.Background()
	if err := h.sessionCache.RemoveTokens(ctx, session.AccessToken, session.RefreshToken); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to remove session tokens from cache: %v", err)
	}
	accessTTL := time.Until(session.AccessExpiry)
	refreshTTL := time.Until(session.RefreshExpiry)
	if accessTTL < 0 {
		accessTTL = 0
	}
	if refreshTTL < 0 {
		refreshTTL = 0
	}
	if err := h.sessionCache.MarkRevoked(ctx, sessioncache.TokenTypeAccess, session.AccessToken, accessTTL); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to cache revoked access token: %v", err)
	}
	if err := h.sessionCache.MarkRevoked(ctx, sessioncache.TokenTypeRefresh, session.RefreshToken, refreshTTL); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to cache revoked refresh token: %v", err)
	}
}

func errorsIsRedisNil(err error) bool {
	return err == nil || errors.Is(err, redis.Nil)
}
