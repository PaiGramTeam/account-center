package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
)

type initiateOAuthRequest struct {
	RedirectTo string `json:"redirect_to"`
}

// InitiateOAuth prepares an OAuth login by issuing a state token.
func (h *Handler) InitiateOAuth(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	providerCfg, ok := h.resolveProvider(provider)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	var req initiateOAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	state, err := randomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate nonce"})
		return
	}

	redirectURL := strings.TrimSpace(req.RedirectTo)
	if redirectURL == "" {
		redirectURL = providerCfg.RedirectURL
	}
	if redirectURL == "" {
		redirectURL = h.cfg.DefaultOAuthRedirectURL
	}

	stateTTL := time.Duration(h.cfg.OAuthStateTTLSeconds) * time.Second
	if stateTTL <= 0 {
		stateTTL = 5 * time.Minute
	}
	expiry := time.Now().UTC().Add(stateTTL)

	stateRecord := model.UserOAuthState{
		Provider:   provider,
		State:      state,
		RedirectTo: redirectURL,
		Nonce:      nonce,
		ExpiresAt:  expiry,
	}
	if err := h.db.Create(&stateRecord).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist oauth state"})
		return
	}

	authURL, err := buildAuthURL(providerCfg, redirectURL, state, nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build auth url"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"state":      state,
			"nonce":      nonce,
			"expires_at": expiry.Format(time.RFC3339),
			"auth_url":   authURL,
		},
	})
}

type oauthCallbackRequest struct {
	State             string `json:"state" binding:"required"`
	Code              string `json:"code"`
	ProviderAccountID string `json:"provider_account_id" binding:"required"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	DisplayName       string `json:"display_name"`
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	ExpiresIn         int    `json:"expires_in"`
	Scope             string `json:"scope"`
}

// HandleOAuthCallback processes the OAuth callback and issues a local session.
func (h *Handler) HandleOAuthCallback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	_, ok := h.resolveProvider(provider)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	var req oauthCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var user model.User
	var emailRecord *model.UserEmail
	var session *model.UserSession

	err := h.db.Transaction(func(tx *gorm.DB) error {
		var stateRecord model.UserOAuthState
		if err := tx.Where("state = ? AND provider = ?", req.State, provider).First(&stateRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("invalid oauth state")
			}
			return err
		}

		if now.After(stateRecord.ExpiresAt) {
			if err := tx.Delete(&stateRecord).Error; err != nil {
				return err
			}
			return fmt.Errorf("oauth state expired")
		}
		if err := tx.Delete(&stateRecord).Error; err != nil {
			return err
		}

		var credential model.UserCredential
		credErr := tx.Where("provider = ? AND provider_account_id = ?", provider, req.ProviderAccountID).First(&credential).Error
		if credErr != nil && !errors.Is(credErr, gorm.ErrRecordNotFound) {
			return credErr
		}

		tokenExpiry := shared.ClearNullTime()
		if req.ExpiresIn > 0 {
			tokenExpiry = shared.MakeNullTime(now.Add(time.Duration(req.ExpiresIn) * time.Second))
		}

		if errors.Is(credErr, gorm.ErrRecordNotFound) {
			user = model.User{
				PrimaryLoginType: model.LoginTypeOAuth,
				Status:           model.UserStatusActive,
			}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}

			displayName := strings.TrimSpace(req.DisplayName)
			if displayName == "" {
				displayName = fmt.Sprintf("%s_user_%s", provider, req.ProviderAccountID)
			}

			profile := model.UserProfile{
				UserID:      user.ID,
				DisplayName: displayName,
				Locale:      "en_US",
			}
			if err := tx.Create(&profile).Error; err != nil {
				return err
			}

			if email := strings.TrimSpace(strings.ToLower(req.Email)); email != "" {
				emailModel := model.UserEmail{
					UserID:    user.ID,
					Email:     email,
					IsPrimary: true,
				}
				if req.EmailVerified {
					emailModel.VerifiedAt = shared.MakeNullTime(now)
				}
				if err := tx.Create(&emailModel).Error; err != nil {
					return err
				}
				emailRecord = &emailModel
			}

			credential = model.UserCredential{
				UserID:            user.ID,
				Provider:          provider,
				ProviderAccountID: req.ProviderAccountID,
				AccessToken:       req.AccessToken,
				RefreshToken:      req.RefreshToken,
				TokenExpiry:       tokenExpiry,
				Scopes:            strings.TrimSpace(req.Scope),
				LastSyncAt:        shared.MakeNullTime(now),
			}
			if err := tx.Create(&credential).Error; err != nil {
				return err
			}
		} else {
			if err := tx.First(&user, credential.UserID).Error; err != nil {
				return err
			}

			update := map[string]interface{}{
				"access_token":  req.AccessToken,
				"refresh_token": req.RefreshToken,
				"token_expiry":  tokenExpiry,
				"scopes":        strings.TrimSpace(req.Scope),
				"last_sync_at":  shared.MakeNullTime(now),
			}
			if err := tx.Model(&model.UserCredential{}).Where("id = ?", credential.ID).Updates(update).Error; err != nil {
				return err
			}

			if email := strings.TrimSpace(strings.ToLower(req.Email)); email != "" {
				var userEmail model.UserEmail
				err := tx.Where("user_id = ? AND email = ?", user.ID, email).First(&userEmail).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						userEmail = model.UserEmail{
							UserID:    user.ID,
							Email:     email,
							IsPrimary: true,
						}
						if req.EmailVerified {
							userEmail.VerifiedAt = shared.MakeNullTime(now)
						}
						if err := tx.Create(&userEmail).Error; err != nil {
							return err
						}
					} else {
						return err
					}
				} else if req.EmailVerified && !userEmail.VerifiedAt.Valid {
					if err := tx.Model(&model.UserEmail{}).Where("id = ?", userEmail.ID).Update("verified_at", shared.MakeNullTime(now)).Error; err != nil {
						return err
					}
				}
				emailRecord = &userEmail
			}
		}

		updates := map[string]interface{}{
			"last_login_at": shared.MakeNullTime(now),
		}
		if user.Status == model.UserStatusPending {
			updates["status"] = model.UserStatusActive
		}
		if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
			return err
		}

		var err error
		session, err = h.issueSession(tx, user.ID, clientIP, userAgent)
		if err != nil {
			return err
		}

		return h.recordLoginAudit(tx, model.LoginAudit{
			UserID:    sql.NullInt64{Int64: int64(user.ID), Valid: true},
			Provider:  provider,
			Success:   true,
			ClientIP:  clientIP,
			UserAgent: userAgent,
			Message:   "oauth login success",
		})
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id":        user.ID,
			"access_token":   session.AccessToken,
			"refresh_token":  session.RefreshToken,
			"access_expiry":  session.AccessExpiry.Format(time.RFC3339),
			"refresh_expiry": session.RefreshExpiry.Format(time.RFC3339),
			"email":          emailValue(emailRecord),
		},
	})
}

func (h *Handler) resolveProvider(provider string) (config.OAuthProviderConfig, bool) {
	if provider == "" {
		return config.OAuthProviderConfig{}, false
	}

	var allowed bool
	if len(h.cfg.AllowedOAuthProviders) == 0 {
		allowed = true
	} else {
		for _, p := range h.cfg.AllowedOAuthProviders {
			if strings.EqualFold(p, provider) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return config.OAuthProviderConfig{}, false
	}

	if h.cfg.OAuthProviders == nil {
		return config.OAuthProviderConfig{}, false
	}

	providerCfg, ok := h.cfg.OAuthProviders[provider]
	if ok {
		return providerCfg, true
	}

	// fall back to case-insensitive lookup
	for key, value := range h.cfg.OAuthProviders {
		if strings.EqualFold(key, provider) {
			return value, true
		}
	}
	return config.OAuthProviderConfig{}, false
}

func buildAuthURL(cfg config.OAuthProviderConfig, redirectURL, state, nonce string) (string, error) {
	if cfg.AuthURL == "" {
		return "", fmt.Errorf("missing auth url for provider")
	}
	authURL, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", err
	}
	query := authURL.Query()
	query.Set("client_id", cfg.ClientID)
	if redirectURL != "" {
		query.Set("redirect_uri", redirectURL)
	} else if cfg.RedirectURL != "" {
		query.Set("redirect_uri", cfg.RedirectURL)
	}
	query.Set("response_type", "code")
	if len(cfg.Scopes) > 0 {
		query.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	query.Set("state", state)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func emailValue(email *model.UserEmail) string {
	if email == nil {
		return ""
	}
	return email.Email
}
