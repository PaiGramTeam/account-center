package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/logging"
	"paigram/internal/model"
	"paigram/internal/response"
	"paigram/internal/sessioncache"
	piiutil "paigram/internal/utils/pii"
)

// ForgotPasswordRequest is the request payload for forgot password
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest is the request payload for reset password
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

// ForgotPassword initiates password reset flow
// @Summary Request password reset
// @Description Send password reset email to user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Forgot password request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 429 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Find user by email
	var user model.User
	var userEmail model.UserEmail
	if err := h.db.Where("email = ? AND is_primary = ?", req.Email, true).
		First(&userEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Don't reveal if email exists or not for security
			response.Success(c, gin.H{
				"message": "if the email exists, a password reset link has been sent",
			})
			return
		}
		logging.Error("failed to query user email",
			zap.Error(err),
			zap.String("email_masked", piiutil.MaskEmail(req.Email)),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get the user
	if err := h.db.First(&user, userEmail.UserID).Error; err != nil {
		logging.Error("failed to query user",
			zap.Error(err),
			zap.Uint64("user_id", userEmail.UserID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Check if user account is active
	if user.Status != model.UserStatusActive {
		response.BadRequestWithCode(c, "ACCOUNT_NOT_ACTIVE", "account is not active", nil)
		return
	}

	// Generate password reset token
	token, tokenHash, err := generatePasswordResetToken()
	if err != nil {
		logging.Error("failed to generate reset token",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Invalidate any existing reset tokens for this user
	if err := h.db.Model(&model.PasswordResetToken{}).
		Where("user_id = ? AND used_at IS NULL", user.ID).
		Updates(map[string]interface{}{
			"used_at": time.Now(),
		}).Error; err != nil {
		logging.Error("failed to invalidate existing tokens",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		// Continue anyway, not a critical error
	}

	// Save reset token to database
	// Calculate token expiry with fallback to default (1 hour, matching better-auth)
	resetTTL := time.Duration(h.cfg.PasswordResetTokenTTLSeconds) * time.Second
	if resetTTL <= 0 {
		resetTTL = 1 * time.Hour // Default: 1 hour (3600 seconds)
	}

	resetToken := &model.PasswordResetToken{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: time.Now().Add(resetTTL),
	}

	if err := h.db.Create(resetToken).Error; err != nil {
		logging.Error("failed to create reset token",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Send password reset email asynchronously to prevent timing attacks.
	// By using a goroutine, the response time is consistent regardless of
	// whether the email exists or not, preventing attackers from determining
	// valid emails based on response time differences.
	//
	// SECURITY: The reset link's host MUST come from server-side configuration
	// (cfg.Frontend.BaseURL). It is intentionally NOT taken from the Origin
	// header — that header is attacker-controlled and would let a malicious
	// caller phish the user via a link to their own domain. If BaseURL is
	// missing we log + skip the send rather than fall back; the user-facing
	// response is unchanged so we don't leak that the deployment is
	// misconfigured.
	baseURL := strings.TrimRight(strings.TrimSpace(h.frontendCfg.BaseURL), "/")
	if baseURL == "" {
		logging.Error("frontend.base_url is not configured; suppressing password-reset email",
			zap.Uint64("user_id", user.ID),
		)
	} else {
		go func(recipient string, userID uint64, plainToken, base string) {
			ctx := context.Background()
			if err := h.dispatchPasswordResetEmail(ctx, recipient, plainToken, base); err != nil {
				logging.Error("failed to send password reset email",
					zap.Error(err),
					zap.Uint64("user_id", userID),
				)
			}
		}(userEmail.Email, user.ID, token, baseURL)
	}

	// Return immediately with consistent timing to prevent timing attacks
	response.Success(c, gin.H{
		"message": "if the email exists, a password reset link has been sent",
	})
}

// ResetPassword resets user password with token
// @Summary Reset password
// @Description Reset user password using reset token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Reset password request"
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 500 {object} response.Response
// @Router /api/v1/auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequestWithCode(c, "INVALID_INPUT", "invalid request", map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Hash the provided token to match database
	tokenHash := hashToken(req.Token)

	// Find valid reset token
	var resetToken model.PasswordResetToken
	if err := h.db.Where("token = ? AND expires_at > ? AND used_at IS NULL", tokenHash, time.Now()).
		First(&resetToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.BadRequestWithCode(c, "INVALID_TOKEN", "invalid or expired reset token", nil)
			return
		}
		logging.Error("failed to query reset token",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Get user
	var user model.User
	if err := h.db.First(&user, resetToken.UserID).Error; err != nil {
		logging.Error("failed to query user",
			zap.Error(err),
			zap.Uint64("user_id", resetToken.UserID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	var credential model.UserCredential
	if err := h.db.Where("user_id = ? AND provider = ?", user.ID, string(model.LoginTypeEmail)).First(&credential).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.NotFoundWithCode(c, "NO_PASSWORD", "user does not have password authentication", nil)
			return
		}
		logging.Error("failed to query user credential",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), h.getBcryptCost())
	if err != nil {
		logging.Error("failed to hash password",
			zap.Error(err),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Update password and mark token as used in a transaction.
	//
	// V15 (commit-boundary nuance): cache writes for session revocation
	// MUST happen AFTER the transaction commits, not inside the closure.
	// Otherwise a transient commit failure (deadlock, connection drop)
	// rolls back the UPDATE but leaves the revocation marker set in
	// Redis. The middleware fast path at internal/middleware/auth.go:88
	// short-circuits on marker presence with NO fallback to DB, so a
	// stray marker locks the user out of the cache fast path until the
	// marker TTL elapses. We therefore have revokeAllUserSessions return
	// the snapshot of revoked sessions and write the cache markers only
	// after Transaction(...) returns nil.
	var revokedSnapshots []model.UserSession
	err = h.db.Transaction(func(tx *gorm.DB) error {
		// Update password
		if err := tx.Model(&model.UserCredential{}).
			Where("id = ?", credential.ID).
			Update("password_hash", string(hashedPassword)).Error; err != nil {
			return fmt.Errorf("update password: %w", err)
		}

		// Mark token as used
		now := time.Now()
		if err := tx.Model(&resetToken).Update("used_at", sql.NullTime{
			Time:  now,
			Valid: true,
		}).Error; err != nil {
			return fmt.Errorf("mark token as used: %w", err)
		}

		// Revoke all active sessions for security. Snapshot the rows we
		// just revoked so the post-commit step below can write the cache
		// markers. revokeAllUserSessions does NOT touch the cache itself.
		snapshots, err := h.revokeAllUserSessions(tx, user.ID)
		if err != nil {
			logging.Warn("failed to revoke sessions",
				zap.Error(err),
				zap.Uint64("user_id", user.ID),
			)
			// Continue anyway — leave revokedSnapshots nil so we don't
			// publish stale markers for a half-finished revoke.
			return nil
		}
		revokedSnapshots = snapshots

		return nil
	})

	if err != nil {
		logging.Error("failed to reset password",
			zap.Error(err),
			zap.Uint64("user_id", user.ID),
		)
		response.InternalServerErrorWithCode(c, "INTERNAL_ERROR", "internal server error", nil)
		return
	}

	// Post-commit: publish per-session revocation markers and clear the
	// current-access-hash markers. See invalidateRevokedSessionsCache for
	// the honest failure-mode contract.
	h.invalidateRevokedSessionsCache(context.Background(), revokedSnapshots)

	// Send password changed notification email asynchronously
	// This prevents response time variations and doesn't block the success response
	go func(userID uint64) {
		// Get primary email
		var userEmail model.UserEmail
		if err := h.db.Where("user_id = ? AND is_primary = ?", userID, true).
			First(&userEmail).Error; err != nil {
			logging.Warn("failed to get user primary email",
				zap.Error(err),
				zap.Uint64("user_id", userID),
			)
			return
		}

		// Use background context since the HTTP request is already complete
		ctx := context.Background()
		if err := h.emailService.SendPasswordChangedEmail(ctx, userEmail.Email); err != nil {
			logging.Error("failed to send password changed email",
				zap.Error(err),
				zap.Uint64("user_id", userID),
			)
		}
	}(user.ID)

	// Return success response immediately
	response.Success(c, gin.H{
		"message": "password has been reset successfully",
	})
}

// dispatchPasswordResetEmail routes the reset email through the test seam
// when set, falling back to the wired email service in production. Keeping
// this in one place ensures every path uses the same dispatcher contract.
func (h *Handler) dispatchPasswordResetEmail(ctx context.Context, to, token, baseURL string) error {
	if h.sendPasswordResetEmail != nil {
		return h.sendPasswordResetEmail(ctx, to, token, baseURL)
	}
	return h.emailService.SendPasswordResetEmail(ctx, to, token, baseURL)
}

// generatePasswordResetToken generates a secure random token
// Returns the plain token (to send to user) and the hashed token (to store in DB)
func generatePasswordResetToken() (plain, hashed string, err error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}

	// Convert to hex string (64 characters)
	plain = hex.EncodeToString(bytes)

	// Hash for storage
	hashed = hashToken(plain)

	return plain, hashed, nil
}

// hashToken is now defined in helpers.go (SHA-256 implementation)

// revokeAllUserSessions revokes all active sessions for a user at the DB
// layer and returns the snapshot of rows that were just revoked so the
// caller can publish cache markers AFTER the surrounding transaction
// commits.
//
// V15: a stolen access token used to remain valid until its TTL expired
// even after a password reset, because the middleware's cache fast path
// (see internal/middleware/auth.go:88) short-circuits on the per-session
// revocation marker. Deleting DB rows alone does nothing for cached
// payloads. The fix is two-step:
//
//  1. revokeAllUserSessions runs INSIDE the password-reset transaction:
//     UPDATE user_sessions SET revoked_at=now, revoked_reason='password_reset'
//     and DELETE user_devices. It does NOT write to the cache.
//  2. The caller writes cache markers AFTER Transaction(...) returns nil
//     via invalidateRevokedSessionsCache. This ordering matters: writing
//     the marker before the commit risks a stray marker on rollback that
//     locks the user out of the cache fast path (the middleware does not
//     fall back to the DB on marker presence — it returns 401 outright),
//     for up to the marker's TTL. Code-review feedback on the V15 commit.
//
// We chose UPDATE-with-revoked_at (option ii) over outright DELETE so the
// audit trail survives. This mirrors the precedent set by the token-reuse
// and rapid-refresh handlers in email.go and the "revoke other sessions"
// path in service/me/security_service.go. UserDevice rows ARE still wiped:
// losing trusted-device state on a password reset is intentional — it
// forces a 2FA re-prompt on the next login.
func (h *Handler) revokeAllUserSessions(tx *gorm.DB, userID uint64) ([]model.UserSession, error) {
	// Snapshot the active sessions so the caller can drive cache marker
	// writes after the transaction commits. The snapshot also gives
	// RevokedSessionMarkerTTL the original RefreshExpiry to size the
	// marker against — UPDATE doesn't touch that column, but we want the
	// snapshot decoupled from any later mutation.
	var sessions []model.UserSession
	if err := tx.Where("user_id = ? AND revoked_at IS NULL", userID).Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("query user sessions: %w", err)
	}

	now := time.Now().UTC()
	if len(sessions) > 0 {
		if err := tx.Model(&model.UserSession{}).
			Where("user_id = ? AND revoked_at IS NULL", userID).
			Updates(map[string]interface{}{
				"revoked_at":     now,
				"revoked_reason": "password_reset",
			}).Error; err != nil {
			return nil, fmt.Errorf("revoke user sessions: %w", err)
		}
	}

	// Delete all user devices: trusted-device state is cleared on password
	// reset by design (forces 2FA re-prompt next login).
	if err := tx.Where("user_id = ?", userID).Delete(&model.UserDevice{}).Error; err != nil {
		return nil, fmt.Errorf("delete user devices: %w", err)
	}

	return sessions, nil
}

// invalidateRevokedSessionsCache publishes per-session revocation markers
// and clears the current-access-hash markers for each session in the
// snapshot. Intended to be called AFTER the password-reset transaction
// commits; see revokeAllUserSessions for the rationale.
//
// Cache marker writes are best-effort and run AFTER the DB commit. If a
// cache write fails (Redis down, network blip), the DB UPDATE has already
// committed — the session is durably revoked. The middleware's cache
// fast path will continue to admit the previously-cached sessionData
// until that data expires (typically minutes-hours), at which point the
// DB-fallback path will see revoked_at IS NOT NULL and reject. That is
// an inherent best-effort property of the cache-revocation design;
// V15's contract is "DB-correct immediately + cache-best-effort".
//
// If you need stronger guarantees (e.g., immediate cache invalidation
// on Redis recovery), consider writing the marker via a retry loop or
// a separate compensating job — both are out of scope here.
func (h *Handler) invalidateRevokedSessionsCache(ctx context.Context, sessions []model.UserSession) {
	for i := range sessions {
		s := &sessions[i]
		if err := h.sessionCache.Set(
			ctx,
			sessioncache.RevokedSessionMarkerKey(s.ID),
			[]byte("1"),
			sessioncache.RevokedSessionMarkerTTL(s),
		); err != nil && !errorsIsRedisNil(err) {
			logging.Warn("failed to write session revocation marker",
				zap.Error(err),
				zap.Uint64("user_id", s.UserID),
				zap.Uint64("session_id", s.ID),
			)
		}
		// Drop the current-access-hash marker so a stale cached
		// tokenPayload also fails the hash-equality check in the
		// middleware fast path. Mirrors clearCurrentAccessHashMarker.
		if err := h.sessionCache.Delete(ctx, sessioncache.CurrentAccessTokenHashKey(s.ID)); err != nil && !errorsIsRedisNil(err) {
			logging.Warn("failed to clear current access token hash marker",
				zap.Error(err),
				zap.Uint64("user_id", s.UserID),
				zap.Uint64("session_id", s.ID),
			)
		}
	}
}
