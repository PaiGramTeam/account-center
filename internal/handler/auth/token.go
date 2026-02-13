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

// SessionWithTokens holds the session record and the original tokens
// The tokens are only returned once during creation and never stored in plain text
type SessionWithTokens struct {
	Session      *model.UserSession
	AccessToken  string // Only available at creation time
	RefreshToken string // Only available at creation time
}

func (h *Handler) issueSession(tx *gorm.DB, userID uint64, clientIP, userAgent string) (*SessionWithTokens, error) {
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

	// Hash the tokens before storing
	session := &model.UserSession{
		UserID:           userID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		AccessExpiry:     now.Add(accessTTL),
		RefreshExpiry:    now.Add(refreshTTL),
		UserAgent:        userAgent,
		ClientIP:         clientIP,
	}

	if err := tx.Create(session).Error; err != nil {
		return nil, err
	}

	// Create or update device record
	deviceID := generateDeviceID(userAgent, clientIP)
	deviceType, os, browser := parseUserAgent(userAgent)
	deviceName := browser + " / " + os

	// Resolve IP location (async to avoid blocking)
	location := ""
	if h.geoService != nil {
		if loc, err := h.geoService.Lookup(clientIP); err == nil {
			location = loc.String()
		}
	}

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
				Location:     location,
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
			"location":       location,
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
		Location:  location,
		Status:    "success",
		CreatedAt: now,
	}
	if err := tx.Create(&loginLog).Error; err != nil {
		log.Printf("failed to create login log: %v", err)
	}

	// Cache session with original tokens for verification
	h.cacheStoreSessionWithTokens(session, accessToken, refreshToken)

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
			h.cacheRevokeSessionTokens(&oldest, "", "")
			sessions = sessions[1:]
		}
	}

	// Return session with original tokens (only time they are in memory)
	return &SessionWithTokens{
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
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

// cacheStoreSessionWithTokens stores session in cache with original tokens
func (h *Handler) cacheStoreSessionWithTokens(session *model.UserSession, accessToken, refreshToken string) {
	if session == nil {
		return
	}
	ctx := context.Background()
	if err := h.sessionCache.SaveSessionWithTokens(ctx, session, accessToken, refreshToken); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to cache session tokens: %v", err)
	}
}

// cacheRevokeSessionTokens removes and marks tokens as revoked in cache
// accessToken and refreshToken are the original (unhashed) tokens
func (h *Handler) cacheRevokeSessionTokens(session *model.UserSession, accessToken, refreshToken string) {
	if session == nil {
		return
	}
	ctx := context.Background()

	// Remove tokens from cache (if provided)
	if accessToken != "" || refreshToken != "" {
		if err := h.sessionCache.RemoveTokens(ctx, accessToken, refreshToken); err != nil && !errorsIsRedisNil(err) {
			log.Printf("failed to remove session tokens from cache: %v", err)
		}
	}

	// Calculate TTL for revoked markers
	accessTTL := time.Until(session.AccessExpiry)
	refreshTTL := time.Until(session.RefreshExpiry)
	if accessTTL < 0 {
		accessTTL = 0
	}
	if refreshTTL < 0 {
		refreshTTL = 0
	}

	// Mark tokens as revoked (if provided)
	if accessToken != "" {
		if err := h.sessionCache.MarkRevoked(ctx, sessioncache.TokenTypeAccess, accessToken, accessTTL); err != nil && !errorsIsRedisNil(err) {
			log.Printf("failed to cache revoked access token: %v", err)
		}
	}
	if refreshToken != "" {
		if err := h.sessionCache.MarkRevoked(ctx, sessioncache.TokenTypeRefresh, refreshToken, refreshTTL); err != nil && !errorsIsRedisNil(err) {
			log.Printf("failed to cache revoked refresh token: %v", err)
		}
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
