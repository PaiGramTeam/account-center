package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"strings"
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

	// Create or update device record
	deviceID := generateDeviceID(userAgent, clientIP)
	deviceType, os, browser := parseUserAgent(userAgent)
	deviceName := browser + " / " + os

	var device model.UserDevice
	err = tx.Where("device_id = ?", deviceID).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new device record
			device = model.UserDevice{
				UserID:       userID,
				DeviceID:     deviceID,
				DeviceName:   deviceName,
				DeviceType:   deviceType,
				OS:           os,
				Browser:      browser,
				IP:           clientIP,
				Location:     "", // Could be populated using IP geolocation service
				LastActiveAt: now,
			}
			if err := tx.Create(&device).Error; err != nil {
				log.Printf("failed to create device record: %v", err)
			}
		} else {
			log.Printf("failed to query device: %v", err)
		}
	} else {
		// Update existing device
		updates := map[string]interface{}{
			"last_active_at": now,
			"ip":             clientIP,
			"device_name":    deviceName,
			"os":             os,
			"browser":        browser,
		}
		if err := tx.Model(&model.UserDevice{}).Where("id = ?", device.ID).Updates(updates).Error; err != nil {
			log.Printf("failed to update device record: %v", err)
		}
	}

	// Log successful login
	loginLog := model.LoginLog{
		UserID:    userID,
		LoginType: model.LoginTypeEmail, // This will be set by the caller
		IP:        clientIP,
		UserAgent: userAgent,
		Device:    deviceName,
		Location:  "", // Could be populated using IP geolocation service
		Status:    "success",
		CreatedAt: now,
	}
	if err := tx.Create(&loginLog).Error; err != nil {
		log.Printf("failed to create login log: %v", err)
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

// generateDeviceID creates a unique device identifier from user agent and IP
func generateDeviceID(userAgent, clientIP string) string {
	data := userAgent + clientIP
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])[:22]
}

// parseUserAgent extracts device info from user agent string
func parseUserAgent(userAgent string) (deviceType, os, browser string) {
	ua := strings.ToLower(userAgent)

	// Detect device type
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		deviceType = "mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		deviceType = "tablet"
	} else {
		deviceType = "desktop"
	}

	// Detect OS
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	default:
		os = "Unknown"
	}

	// Detect browser
	switch {
	case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edge"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "edge"):
		browser = "Edge"
	case strings.Contains(ua, "opera"):
		browser = "Opera"
	default:
		browser = "Unknown"
	}

	return
}
