package me

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/sessioncache"
	"paigram/internal/utils/secsubtle"
)

// SessionView represents the /me session payload.
type SessionView struct {
	ID            uint64     `json:"id"`
	DeviceID      string     `json:"device_id,omitempty"`
	DeviceName    string     `json:"device_name,omitempty"`
	DeviceType    string     `json:"device_type,omitempty"`
	IP            string     `json:"ip,omitempty"`
	Location      string     `json:"location,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
	AccessExpiry  time.Time  `json:"access_expiry"`
	RefreshExpiry time.Time  `json:"refresh_expiry"`
	IsCurrent     bool       `json:"is_current"`
}

// SessionService serves current-user sessions.
type SessionService struct {
	db    *gorm.DB
	cache sessioncache.Store
}

// NewSessionService creates a session service.
func NewSessionService(db *gorm.DB, cache sessioncache.Store) *SessionService {
	return &SessionService{db: db, cache: cache}
}

// ListSessions returns active sessions for the current user.
func (s *SessionService) ListSessions(ctx context.Context, userID uint64, page, pageSize int, accessToken string) ([]SessionView, int64, error) {
	var total int64
	baseQuery := s.db.WithContext(ctx).Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var sessions []model.UserSession
	offset := (page - 1) * pageSize
	if err := baseQuery.Order("created_at DESC, id DESC").Offset(offset).Limit(pageSize).Find(&sessions).Error; err != nil {
		return nil, 0, err
	}

	var devices []model.UserDevice
	deviceMap := map[string]model.UserDevice{}
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&devices).Error; err == nil {
		for _, device := range devices {
			deviceMap[device.DeviceID] = device
		}
	}

	currentTokenHash := hashBearerToken(accessToken)
	views := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		view := SessionView{
			ID:            session.ID,
			IP:            session.ClientIP,
			CreatedAt:     session.CreatedAt,
			AccessExpiry:  session.AccessExpiry,
			RefreshExpiry: session.RefreshExpiry,
			IsCurrent:     currentTokenHash != "" && secsubtle.StringEqual(session.AccessTokenHash, currentTokenHash),
		}
		deviceID := buildDeviceID(session.UserAgent, session.ClientIP)
		if device, ok := deviceMap[deviceID]; ok {
			view.DeviceID = device.DeviceID
			view.DeviceName = device.DeviceName
			view.DeviceType = device.DeviceType
			view.Location = device.Location
			lastActive := device.LastActiveAt
			view.LastActiveAt = &lastActive
		}
		views = append(views, view)
	}
	return views, total, nil
}

// RevokeSession revokes a specific current-user session.
func (s *SessionService) RevokeSession(ctx context.Context, userID, sessionID uint64) error {
	if sessionID == 0 {
		return ErrInvalidSessionID
	}

	var session model.UserSession
	if err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", sessionID, userID).First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrSessionNotFound
		}
		return err
	}
	if session.RevokedAt.Valid {
		return nil
	}

	now := time.Now().UTC()
	updates := map[string]any{
		"revoked_at":     sql.NullTime{Time: now, Valid: true},
		"revoked_reason": "revoked by user",
	}
	if err := s.db.WithContext(ctx).Model(&session).Updates(updates).Error; err != nil {
		return err
	}
	return s.cache.Set(ctx, sessioncache.RevokedSessionMarkerKey(session.ID), []byte("1"), sessioncache.RevokedSessionMarkerTTL(&session))
}

func hashBearerToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func buildDeviceID(userAgent, clientIP string) string {
	if userAgent == "" && clientIP == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(userAgent + clientIP))
	return base64.URLEncoding.EncodeToString(hash[:])[:22]
}
