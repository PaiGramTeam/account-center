package me

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"paigram/internal/crypto"
	"paigram/internal/model"
	"paigram/internal/sessioncache"
)

const defaultBcryptCost = 12

// SecurityOverview captures the self-service security posture.
type SecurityOverview struct {
	UserID                 uint64     `json:"user_id"`
	TwoFactorEnabled       bool       `json:"two_factor_enabled"`
	ActiveSessionCount     int64      `json:"active_session_count"`
	DeviceCount            int64      `json:"device_count"`
	FailedLoginsLast30Days int64      `json:"failed_logins_last_30_days"`
	LastLoginAt            *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP            string     `json:"last_login_ip,omitempty"`
	LastLoginDevice        string     `json:"last_login_device,omitempty"`
	LastLoginLocation      string     `json:"last_login_location,omitempty"`
}

// UpdatePasswordInput describes a self-service password change.
type UpdatePasswordInput struct {
	UserID               uint64
	OldPassword          string
	NewPassword          string
	RevokeOtherSessions  bool
	CurrentAccessToken   string
	ClientIP             string
	UserAgent            string
}

// SetupTwoFactorInput describes a 2FA setup request.
type SetupTwoFactorInput struct {
	UserID   uint64
	Password string
}

// TwoFactorSetupView contains secret material for initial 2FA setup.
type TwoFactorSetupView struct {
	QRCode      string    `json:"qr_code"`
	Secret      string    `json:"secret"`
	BackupCodes []string  `json:"backup_codes"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ConfirmTwoFactorInput confirms a 2FA setup.
type ConfirmTwoFactorInput struct {
	UserID    uint64
	Code      string
	ClientIP  string
	UserAgent string
}

// DisableTwoFactorInput disables 2FA.
type DisableTwoFactorInput struct {
	UserID    uint64
	Password  string
	Code      string
	ClientIP  string
	UserAgent string
}

// RegenerateBackupCodesInput refreshes stored backup codes.
type RegenerateBackupCodesInput struct {
	UserID    uint64
	Password  string
	ClientIP  string
	UserAgent string
}

type twoFactorSetupData struct {
	Secret      string    `json:"secret"`
	BackupCodes []string  `json:"backup_codes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SecurityService serves /me security endpoints.
type SecurityService struct {
	db    *gorm.DB
	cache sessioncache.Store
}

// NewSecurityService creates a security service.
func NewSecurityService(db *gorm.DB, cache sessioncache.Store) *SecurityService {
	return &SecurityService{db: db, cache: cache}
}

// GetOverview loads the current-user security summary.
func (s *SecurityService) GetOverview(ctx context.Context, userID uint64) (*SecurityOverview, error) {
	overview := &SecurityOverview{UserID: userID}

	var twoFactor model.UserTwoFactor
	err := s.db.WithContext(ctx).Where("user_id = ?", userID).First(&twoFactor).Error
	if err == nil {
		overview.TwoFactorEnabled = true
	} else if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if err := s.db.WithContext(ctx).Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL", userID).Count(&overview.ActiveSessionCount).Error; err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Model(&model.UserDevice{}).Where("user_id = ?", userID).Count(&overview.DeviceCount).Error; err != nil {
		return nil, err
	}
	since := time.Now().UTC().AddDate(0, 0, -30)
	if err := s.db.WithContext(ctx).Model(&model.LoginLog{}).Where("user_id = ? AND status = ? AND created_at >= ?", userID, "failed", since).Count(&overview.FailedLoginsLast30Days).Error; err != nil {
		return nil, err
	}

	var lastLogin model.LoginLog
	err = s.db.WithContext(ctx).Where("user_id = ? AND status = ?", userID, "success").Order("created_at DESC").First(&lastLogin).Error
	if err == nil {
		overview.LastLoginAt = &lastLogin.CreatedAt
		overview.LastLoginIP = lastLogin.IP
		overview.LastLoginDevice = lastLogin.Device
		overview.LastLoginLocation = lastLogin.Location
	} else if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	return overview, nil
}

// UpdatePassword changes the current-user password.
func (s *SecurityService) UpdatePassword(ctx context.Context, input UpdatePasswordInput) error {
	cred, err := s.loadPasswordCredential(ctx, input.UserID)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(input.OldPassword)); err != nil {
		return ErrInvalidPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), defaultBcryptCost)
	if err != nil {
		return err
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.UserCredential{}).Where("id = ?", cred.ID).Update("password_hash", string(hashedPassword)).Error; err != nil {
			return err
		}
		auditLog := model.AuditLog{
			UserID:     input.UserID,
			Action:     "password_change",
			Resource:   "user_credential",
			ResourceID: cred.ID,
			IP:         input.ClientIP,
			UserAgent:  input.UserAgent,
			Details:    fmt.Sprintf(`{"reason":"user_requested","revoke_other_sessions":%t}`, input.RevokeOtherSessions),
			CreatedAt:  time.Now().UTC(),
		}
		if err := tx.Create(&auditLog).Error; err != nil {
			return err
		}
		if !input.RevokeOtherSessions {
			return nil
		}
		currentTokenHash := hashBearerToken(input.CurrentAccessToken)
		var otherSessions []model.UserSession
		if err := tx.Where("user_id = ? AND revoked_at IS NULL AND access_token_hash != ?", input.UserID, currentTokenHash).Find(&otherSessions).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.UserSession{}).Where("user_id = ? AND revoked_at IS NULL AND access_token_hash != ?", input.UserID, currentTokenHash).Updates(map[string]any{"revoked_at": time.Now().UTC(), "revoked_reason": "password_changed"}).Error; err != nil {
			return err
		}
		for i := range otherSessions {
			_ = s.cache.Set(ctx, sessioncache.RevokedSessionMarkerKey(otherSessions[i].ID), []byte("1"), sessioncache.RevokedSessionMarkerTTL(&otherSessions[i]))
		}
		return nil
	})
}

// SetupTwoFactor creates a new temporary 2FA setup challenge.
func (s *SecurityService) SetupTwoFactor(ctx context.Context, input SetupTwoFactorInput) (*TwoFactorSetupView, error) {
	cred, err := s.loadPasswordCredential(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(input.Password)); err != nil {
		return nil, ErrInvalidPassword
	}
	var existing model.UserTwoFactor
	err = s.db.WithContext(ctx).Where("user_id = ?", input.UserID).First(&existing).Error
	if err == nil {
		return nil, ErrTwoFactorAlreadyEnabled
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	var user model.User
	if err := s.db.WithContext(ctx).Preload("Profile").First(&user, input.UserID).Error; err != nil {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Paigram", AccountName: user.Profile.DisplayName})
	if err != nil {
		return nil, err
	}
	backupCodes, err := generateBackupCodes()
	if err != nil {
		return nil, err
	}
	setup := twoFactorSetupData{Secret: key.Secret(), BackupCodes: backupCodes, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}
	data, err := json.Marshal(setup)
	if err != nil {
		return nil, err
	}
	if err := s.cache.Set(ctx, twoFactorSetupCacheKey(input.UserID), data, 15*time.Minute); err != nil {
		return nil, err
	}
	return &TwoFactorSetupView{QRCode: key.URL(), Secret: key.Secret(), BackupCodes: backupCodes, ExpiresAt: setup.ExpiresAt}, nil
}

// ConfirmTwoFactor activates a previously prepared 2FA setup.
func (s *SecurityService) ConfirmTwoFactor(ctx context.Context, input ConfirmTwoFactorInput) error {
	setup, err := s.loadTwoFactorSetup(ctx, input.UserID)
	if err != nil {
		return err
	}
	valid, err := totp.ValidateCustom(input.Code, setup.Secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil || !valid {
		return ErrInvalidTwoFactorCode
	}

	hashedCodes := make([]string, len(setup.BackupCodes))
	for i, code := range setup.BackupCodes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), defaultBcryptCost)
		if err != nil {
			return err
		}
		hashedCodes[i] = string(hashed)
	}
	backupCodesJSON, err := json.Marshal(hashedCodes)
	if err != nil {
		return err
	}
	encryptedSecret, err := crypto.Encrypt(setup.Secret)
	if err != nil {
		return err
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		twoFactor := model.UserTwoFactor{UserID: input.UserID, Secret: encryptedSecret, BackupCodes: string(backupCodesJSON), EnabledAt: time.Now().UTC()}
		if err := tx.Create(&twoFactor).Error; err != nil {
			return err
		}
		auditLog := model.AuditLog{UserID: input.UserID, Action: "2fa_enabled", Resource: "user_two_factor", ResourceID: twoFactor.ID, IP: input.ClientIP, UserAgent: input.UserAgent, CreatedAt: time.Now().UTC()}
		return tx.Create(&auditLog).Error
	})
	if err != nil {
		return err
	}
	return s.cache.Delete(ctx, twoFactorSetupCacheKey(input.UserID))
}

// DisableTwoFactor disables the current-user 2FA configuration.
func (s *SecurityService) DisableTwoFactor(ctx context.Context, input DisableTwoFactorInput) error {
	cred, err := s.loadPasswordCredential(ctx, input.UserID)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(input.Password)); err != nil {
		return ErrInvalidPassword
	}
	var twoFactor model.UserTwoFactor
	if err := s.db.WithContext(ctx).Where("user_id = ?", input.UserID).First(&twoFactor).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrTwoFactorNotEnabled
		}
		return err
	}
	secret, err := crypto.Decrypt(twoFactor.Secret)
	if err != nil {
		return err
	}
	if valid, err := totp.ValidateCustom(input.Code, secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}); err != nil || !valid {
		return ErrInvalidTwoFactorCode
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&twoFactor).Error; err != nil {
			return err
		}
		auditLog := model.AuditLog{UserID: input.UserID, Action: "2fa_disabled", Resource: "user_two_factor", ResourceID: twoFactor.ID, IP: input.ClientIP, UserAgent: input.UserAgent, CreatedAt: time.Now().UTC()}
		return tx.Create(&auditLog).Error
	})
}

// RegenerateBackupCodes refreshes the current-user backup codes.
func (s *SecurityService) RegenerateBackupCodes(ctx context.Context, input RegenerateBackupCodesInput) ([]string, error) {
	cred, err := s.loadPasswordCredential(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(input.Password)); err != nil {
		return nil, ErrInvalidPassword
	}
	var twoFactor model.UserTwoFactor
	if err := s.db.WithContext(ctx).Where("user_id = ?", input.UserID).First(&twoFactor).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrTwoFactorNotEnabled
		}
		return nil, err
	}
	backupCodes, err := generateBackupCodes()
	if err != nil {
		return nil, err
	}
	hashedCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), defaultBcryptCost)
		if err != nil {
			return nil, err
		}
		hashedCodes[i] = string(hashed)
	}
	backupCodesJSON, err := json.Marshal(hashedCodes)
	if err != nil {
		return nil, err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&twoFactor).Update("backup_codes", string(backupCodesJSON)).Error; err != nil {
			return err
		}
		auditLog := model.AuditLog{UserID: input.UserID, Action: "2fa_backup_codes_regenerated", Resource: "user_two_factor", ResourceID: twoFactor.ID, IP: input.ClientIP, UserAgent: input.UserAgent, Details: `{"codes_count":10}`, CreatedAt: time.Now().UTC()}
		return tx.Create(&auditLog).Error
	})
	if err != nil {
		return nil, err
	}
	return backupCodes, nil
}

func (s *SecurityService) loadPasswordCredential(ctx context.Context, userID uint64) (*model.UserCredential, error) {
	var cred model.UserCredential
	if err := s.db.WithContext(ctx).Where("user_id = ? AND provider = ?", userID, "email").First(&cred).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrNoPasswordLogin
		}
		return nil, err
	}
	return &cred, nil
}

func (s *SecurityService) loadTwoFactorSetup(ctx context.Context, userID uint64) (*twoFactorSetupData, error) {
	data, err := s.cache.Get(ctx, twoFactorSetupCacheKey(userID))
	if err != nil {
		return nil, ErrTwoFactorSetupExpired
	}
	var setup twoFactorSetupData
	if err := json.Unmarshal(data, &setup); err != nil {
		return nil, err
	}
	if time.Now().After(setup.ExpiresAt) {
		_ = s.cache.Delete(ctx, twoFactorSetupCacheKey(userID))
		return nil, ErrTwoFactorSetupExpired
	}
	return &setup, nil
}

func twoFactorSetupCacheKey(userID uint64) string {
	return fmt.Sprintf("2fa_setup:%d", userID)
}

func generateBackupCodes() ([]string, error) {
	backupCodes := make([]string, 10)
	for i := range backupCodes {
		code := make([]byte, 5)
		if _, err := rand.Read(code); err != nil {
			return nil, err
		}
		backupCodes[i] = fmt.Sprintf("%010d", int(code[0])<<32|int(code[1])<<24|int(code[2])<<16|int(code[3])<<8|int(code[4]))
	}
	return backupCodes, nil
}
