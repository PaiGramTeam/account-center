package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/handler/shared"
	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

type registerEmailRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
	DisplayName string `json:"display_name" binding:"required"`
	Locale      string `json:"locale"`
}

// RegisterEmail handles registration via email + password.
func (h *Handler) RegisterEmail(c *gin.Context) {
	var req registerEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}

	var existing model.UserEmail
	if err := h.db.Where("email = ?", email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check email uniqueness"})
		return
	}

	passwordHash, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	verificationToken, err := randomToken(48)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate verification token"})
		return
	}

	verificationTTL := time.Duration(h.cfg.EmailVerificationTTLSeconds) * time.Second
	if verificationTTL <= 0 {
		verificationTTL = 24 * time.Hour
	}
	verificationExpiry := time.Now().UTC().Add(verificationTTL)

	var user model.User
	err = h.db.Transaction(func(tx *gorm.DB) error {
		user = model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusPending,
		}

		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		profile := model.UserProfile{
			UserID:      user.ID,
			DisplayName: displayName,
			Locale:      defaultLocale(req.Locale),
		}
		if err := tx.Create(&profile).Error; err != nil {
			return err
		}

		credential := model.UserCredential{
			UserID:            user.ID,
			Provider:          string(model.LoginTypeEmail),
			ProviderAccountID: email,
			PasswordHash:      passwordHash,
		}
		if err := tx.Create(&credential).Error; err != nil {
			return err
		}

		emailRecord := model.UserEmail{
			UserID:             user.ID,
			Email:              email,
			IsPrimary:          true,
			VerificationToken:  verificationToken,
			VerificationExpiry: shared.MakeNullTime(verificationExpiry),
		}
		if err := tx.Create(&emailRecord).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"user_id":                     user.ID,
			"email":                       email,
			"verification_token":          verificationToken,
			"verification_expires_at":     verificationExpiry.Format(time.RFC3339),
			"requires_email_verification": h.cfg.RequireEmailVerificationLogin,
		},
	})
}

type loginEmailRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginWithEmail authenticates a user via email/password.
func (h *Handler) LoginWithEmail(c *gin.Context) {
	var req loginEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	var emailRecord model.UserEmail
	if err := h.db.Where("email = ?", email).First(&emailRecord).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load credentials"})
		return
	}

	var user model.User
	if err := h.db.First(&user, emailRecord.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}

	if user.Status == model.UserStatusSuspended || user.Status == model.UserStatusDeleted {
		_ = h.recordLoginAudit(h.db, model.LoginAudit{
			UserID:   sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider: string(model.LoginTypeEmail),
			Success:  false,
			ClientIP: c.ClientIP(),
			Message:  fmt.Sprintf("user status %s not allowed to login", user.Status),
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "account is not allowed to login"})
		return
	}

	var credential model.UserCredential
	if err := h.db.Where("user_id = ? AND provider = ? AND provider_account_id = ?", user.ID, string(model.LoginTypeEmail), email).
		First(&credential).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := comparePassword(credential.PasswordHash, req.Password); err != nil {
		_ = h.recordLoginAudit(h.db, model.LoginAudit{
			UserID:   sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider: string(model.LoginTypeEmail),
			Success:  false,
			ClientIP: c.ClientIP(),
			Message:  "password mismatch",
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if h.cfg.RequireEmailVerificationLogin && (!emailRecord.VerifiedAt.Valid || emailRecord.VerifiedAt.Time.IsZero()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "email not verified"})
		return
	}

	var session *model.UserSession
	now := time.Now().UTC()
	err := h.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]interface{}{
			"last_login_at": shared.MakeNullTime(now),
		}
		if user.Status == model.UserStatusPending && (!h.cfg.RequireEmailVerificationLogin || emailRecord.VerifiedAt.Valid) {
			updates["status"] = model.UserStatusActive
		}

		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
			return err
		}

		var err error
		session, err = h.issueSession(tx, user.ID, c.ClientIP(), c.GetHeader("User-Agent"))
		if err != nil {
			return err
		}

		return h.recordLoginAudit(tx, model.LoginAudit{
			UserID:    sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider:  string(model.LoginTypeEmail),
			Success:   true,
			ClientIP:  c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Message:   "login success",
		})
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id":        user.ID,
			"access_token":   session.AccessToken,
			"refresh_token":  session.RefreshToken,
			"access_expiry":  session.AccessExpiry.Format(time.RFC3339),
			"refresh_expiry": session.RefreshExpiry.Format(time.RFC3339),
		},
	})
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshToken exchanges a refresh token for a new pair.
func (h *Handler) RefreshToken(c *gin.Context) {
	var req refreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	if revoked, err := h.sessionCache.IsRevoked(ctx, sessioncache.TokenTypeRefresh, req.RefreshToken); err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to query refresh token revocation: %v", err)
	} else if revoked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
		return
	}

	var session model.UserSession
	var sessionID uint64
	if id, err := h.sessionCache.GetSessionID(ctx, sessioncache.TokenTypeRefresh, req.RefreshToken); err == nil {
		sessionID = id
	} else if err != nil && !errorsIsRedisNil(err) {
		log.Printf("failed to get session id from cache: %v", err)
	}

	var err error
	if sessionID > 0 {
		err = h.db.First(&session, sessionID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = h.db.Where("refresh_token = ?", req.RefreshToken).First(&session).Error
		}
	} else {
		err = h.db.Where("refresh_token = ?", req.RefreshToken).First(&session).Error
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load session"})
		return
	}

	if session.RevokedAt.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
		return
	}

	now := time.Now().UTC()
	if now.After(session.RefreshExpiry) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	var user model.User
	if err := h.db.First(&user, session.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}

	prevSession := session
	var newSession model.UserSession
	err = h.db.Transaction(func(tx *gorm.DB) error {
		accessToken, err := randomToken(48)
		if err != nil {
			return err
		}
		refreshToken, err := randomToken(64)
		if err != nil {
			return err
		}

		accessTTL := time.Duration(h.cfg.AccessTokenTTLSeconds) * time.Second
		if accessTTL <= 0 {
			accessTTL = 15 * time.Minute
		}
		refreshTTL := time.Duration(h.cfg.RefreshTokenTTLSeconds) * time.Second
		if refreshTTL <= 0 {
			refreshTTL = 7 * 24 * time.Hour
		}

		updates := map[string]interface{}{
			"access_token":   accessToken,
			"refresh_token":  refreshToken,
			"access_expiry":  now.Add(accessTTL),
			"refresh_expiry": now.Add(refreshTTL),
		}

		if err := tx.Model(&model.UserSession{}).Where("id = ?", session.ID).Updates(updates).Error; err != nil {
			return err
		}

		if err := tx.First(&newSession, session.ID).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	h.cacheRevokeSessionTokens(&prevSession)
	h.cacheStoreSession(&newSession)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id":        newSession.UserID,
			"access_token":   newSession.AccessToken,
			"refresh_token":  newSession.RefreshToken,
			"access_expiry":  newSession.AccessExpiry.Format(time.RFC3339),
			"refresh_expiry": newSession.RefreshExpiry.Format(time.RFC3339),
		},
	})
}

type logoutRequest struct {
	Token string `json:"token" binding:"required"`
}

// Logout revokes an access or refresh token.
func (h *Handler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var session model.UserSession
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("access_token = ? OR refresh_token = ?", req.Token, req.Token).First(&session).Error; err != nil {
			return err
		}
		if session.RevokedAt.Valid {
			return nil
		}
		return h.revokeSession(tx, &session, "user_logout")
	})

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusOK, gin.H{"data": gin.H{"message": "already logged out"}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}

	h.cacheRevokeSessionTokens(&session)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{"message": "logout successful"},
	})
}

type verifyEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
	Token string `json:"token" binding:"required"`
}

// VerifyEmail handles email verification.
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req verifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	err := h.db.Transaction(func(tx *gorm.DB) error {
		var emailRecord model.UserEmail
		if err := tx.Where("email = ?", email).First(&emailRecord).Error; err != nil {
			return err
		}

		if emailRecord.VerificationToken == "" {
			if emailRecord.VerifiedAt.Valid {
				return nil
			}
			return fmt.Errorf("no verification token present")
		}

		if emailRecord.VerificationToken != req.Token {
			return fmt.Errorf("invalid token")
		}

		if emailRecord.VerificationExpiry.Valid && time.Now().UTC().After(emailRecord.VerificationExpiry.Time) {
			return fmt.Errorf("verification token expired")
		}

		update := map[string]interface{}{
			"verified_at":         shared.MakeNullTime(time.Now().UTC()),
			"verification_token":  "",
			"verification_expiry": shared.ClearNullTime(),
		}
		if err := tx.Model(&model.UserEmail{}).Where("id = ?", emailRecord.ID).Updates(update).Error; err != nil {
			return err
		}

		return tx.Model(&model.User{}).
			Where("id = ? AND status = ?", emailRecord.UserID, model.UserStatusPending).
			Update("status", model.UserStatusActive).Error
	})

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "email not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": gin.H{"message": "email verified"}})
}

func defaultLocale(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "en_US"
	}
	return trimmed
}
