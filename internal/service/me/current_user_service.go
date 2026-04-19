package me

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

// CurrentUserView is the phase-two self-service profile response.
type CurrentUserView struct {
	ID           uint64            `json:"id"`
	DisplayName  string            `json:"display_name"`
	AvatarURL    string            `json:"avatar_url,omitempty"`
	Bio          string            `json:"bio,omitempty"`
	Locale       string            `json:"locale,omitempty"`
	Status       model.UserStatus  `json:"status"`
	PrimaryEmail string            `json:"primary_email,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
	Permissions  []string          `json:"permissions,omitempty"`
	Emails       []EmailView       `json:"emails"`
	LoginMethods []LoginMethodView `json:"login_methods"`
	LastLoginAt  *time.Time        `json:"last_login_at,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// DashboardSummaryView is the phase-two self-service dashboard aggregate.
type DashboardSummaryView struct {
	TotalBindings           int64 `json:"total_bindings"`
	ActiveBindings          int64 `json:"active_bindings"`
	InvalidBindings         int64 `json:"invalid_bindings"`
	RefreshRequiredBindings int64 `json:"refresh_required_bindings"`
	TotalProfiles           int64 `json:"total_profiles"`
	EnabledConsumers        int64 `json:"enabled_consumers"`
}

// EmailView is a current-user email projection.
type EmailView struct {
	ID         uint64     `json:"id"`
	Email      string     `json:"email"`
	IsPrimary  bool       `json:"is_primary"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// CreatedEmailView is returned after creating a new email.
type CreatedEmailView struct {
	EmailView
	VerificationToken     string    `json:"-"`
	VerificationExpiresAt time.Time `json:"verification_expires_at"`
}

// VerificationEmailView is returned after resending email verification.
type VerificationEmailView struct {
	VerificationExpiresAt string `json:"verification_expires_at"`
}

// LoginMethodView is a current-user login-method projection.
type LoginMethodView struct {
	Provider          string    `json:"provider"`
	ProviderAccountID string    `json:"provider_account_id"`
	DisplayName       string    `json:"display_name,omitempty"`
	AvatarURL         string    `json:"avatar_url,omitempty"`
	IsPrimary         bool      `json:"is_primary"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateEmailInput describes a new alternate email.
type CreateEmailInput struct {
	UserID          uint64
	Email           string
	VerificationTTL time.Duration
}

// PutLoginMethodInput describes a self-service login-method bind request.
type PutLoginMethodInput struct {
	UserID       uint64
	Provider     string
	ProviderData map[string]any
}

// VerifyEmailInput describes a resend-verification request.
type VerifyEmailInput struct {
	UserID          uint64
	EmailID         uint64
	VerificationTTL time.Duration
}

// CurrentUserService serves the /me current-user surface.
type CurrentUserService struct {
	db *gorm.DB
}

// NewCurrentUserService creates a current-user service.
func NewCurrentUserService(db *gorm.DB) *CurrentUserService {
	return &CurrentUserService{db: db}
}

// GetCurrentUserView loads the current-user profile projection.
func (s *CurrentUserService) GetCurrentUserView(ctx context.Context, userID uint64) (*CurrentUserView, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Preload("Profile").Preload("Emails").Preload("Credentials").First(&user, userID).Error; err != nil {
		return nil, err
	}

	emails := buildEmailViews(user.Emails)
	loginMethods := buildLoginMethodViews(user.PrimaryLoginType, user.Credentials)
	roles, err := s.loadRoleNames(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	permissions, err := s.loadPermissionNames(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	view := &CurrentUserView{
		ID:           user.ID,
		DisplayName:  user.Profile.DisplayName,
		AvatarURL:    user.Profile.AvatarURL,
		Bio:          user.Profile.Bio,
		Locale:       user.Profile.Locale,
		Status:       user.Status,
		PrimaryEmail: primaryEmail(user.Emails),
		Roles:        roles,
		Permissions:  permissions,
		Emails:       emails,
		LoginMethods: loginMethods,
		LastLoginAt:  nullTimePtr(user.LastLoginAt),
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
	return view, nil
}

func (s *CurrentUserService) loadRoleNames(ctx context.Context, userID uint64) ([]string, error) {
	var userRoles []model.UserRole
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Preload("Role").Order("created_at ASC").Find(&userRoles).Error; err != nil {
		return nil, err
	}

	roles := make([]string, 0, len(userRoles))
	for _, userRole := range userRoles {
		if userRole.Role.Name != "" {
			roles = append(roles, userRole.Role.Name)
		}
	}

	return roles, nil
}

func (s *CurrentUserService) loadPermissionNames(ctx context.Context, userID uint64) ([]string, error) {
	var permissions []model.Permission
	err := s.db.WithContext(ctx).Distinct().
		Model(&model.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Order("permissions.name ASC").
		Find(&permissions).Error
	if err != nil {
		return nil, err
	}

	permissionNames := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permissionNames = append(permissionNames, permission.Name)
	}

	return permissionNames, nil
}

// GetDashboardSummary loads the current-user dashboard aggregate.
func (s *CurrentUserService) GetDashboardSummary(ctx context.Context, userID uint64) (*DashboardSummaryView, error) {
	db := s.db.WithContext(ctx)
	summary := &DashboardSummaryView{}

	if err := db.Model(&model.PlatformAccountBinding{}).Where("owner_user_id = ?", userID).Count(&summary.TotalBindings).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.PlatformAccountBinding{}).Where("owner_user_id = ? AND status = ?", userID, model.PlatformAccountBindingStatusActive).Count(&summary.ActiveBindings).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.PlatformAccountBinding{}).Where("owner_user_id = ? AND status = ?", userID, model.PlatformAccountBindingStatusCredentialInvalid).Count(&summary.InvalidBindings).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.PlatformAccountBinding{}).Where("owner_user_id = ? AND status = ?", userID, model.PlatformAccountBindingStatusRefreshRequired).Count(&summary.RefreshRequiredBindings).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.PlatformAccountProfile{}).
		Joins("JOIN platform_account_bindings ON platform_account_bindings.id = platform_account_profiles.binding_id").
		Where("platform_account_bindings.owner_user_id = ?", userID).
		Count(&summary.TotalProfiles).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.ConsumerGrant{}).
		Joins("JOIN platform_account_bindings ON platform_account_bindings.id = consumer_grants.binding_id").
		Where("platform_account_bindings.owner_user_id = ? AND consumer_grants.status = ?", userID, model.ConsumerGrantStatusActive).
		Count(&summary.EnabledConsumers).Error; err != nil {
		return nil, err
	}

	return summary, nil
}

// ListEmails returns current-user email addresses.
func (s *CurrentUserService) ListEmails(ctx context.Context, userID uint64) ([]EmailView, error) {
	var emails []model.UserEmail
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("is_primary DESC, id ASC").Find(&emails).Error; err != nil {
		return nil, err
	}
	return buildEmailViews(emails), nil
}

// CreateEmail adds a new alternate email address for the current user.
func (s *CurrentUserService) CreateEmail(ctx context.Context, input CreateEmailInput) (*CreatedEmailView, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, fmt.Errorf("parse email: %w", err)
	}

	var user model.User
	if err := s.db.WithContext(ctx).First(&user, input.UserID).Error; err != nil {
		return nil, err
	}

	var existing model.UserEmail
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&existing).Error
	if err == nil {
		if existing.UserID == input.UserID {
			return nil, ErrEmailAlreadyAddedToAccount
		}
		return nil, ErrEmailAlreadyInUse
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	verificationTTL := input.VerificationTTL
	if verificationTTL <= 0 {
		verificationTTL = 24 * time.Hour
	}
	verificationToken, err := generateVerificationToken()
	if err != nil {
		return nil, err
	}
	verificationTokenHash := hashVerificationToken(verificationToken)
	verificationExpiry := time.Now().UTC().Add(verificationTTL)

	record := model.UserEmail{
		UserID:             input.UserID,
		Email:              email,
		VerificationToken:  verificationTokenHash,
		VerificationExpiry: sql.NullTime{Time: verificationExpiry, Valid: true},
	}
	if err := s.db.WithContext(ctx).Create(&record).Error; err != nil {
		return nil, err
	}

	return &CreatedEmailView{
		EmailView: EmailView{
			ID:         record.ID,
			Email:      record.Email,
			IsPrimary:  record.IsPrimary,
			VerifiedAt: nullTimePtr(record.VerifiedAt),
			CreatedAt:  record.CreatedAt,
			UpdatedAt:  record.UpdatedAt,
		},
		VerificationToken:     verificationToken,
		VerificationExpiresAt: verificationExpiry,
	}, nil
}

// PatchPrimaryEmail promotes an existing verified email address.
func (s *CurrentUserService) PatchPrimaryEmail(ctx context.Context, userID, emailID uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var email model.UserEmail
		if err := tx.Where("id = ? AND user_id = ?", emailID, userID).First(&email).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return ErrEmailNotFound
			}
			return err
		}
		if !email.VerifiedAt.Valid {
			return ErrEmailNotVerified
		}
		if email.IsPrimary {
			return nil
		}
		if err := tx.Model(&model.UserEmail{}).Where("user_id = ? AND is_primary = ?", userID, true).Update("is_primary", false).Error; err != nil {
			return err
		}
		return tx.Model(&model.UserEmail{}).Where("id = ?", email.ID).Update("is_primary", true).Error
	})
}

// DeleteEmail removes an alternate email for the current user.
func (s *CurrentUserService) DeleteEmail(ctx context.Context, userID, emailID uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var emailRecord model.UserEmail
		if err := tx.Where("id = ? AND user_id = ?", emailID, userID).First(&emailRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrEmailNotFound
			}
			return err
		}

		var emailCount int64
		if err := tx.Model(&model.UserEmail{}).Where("user_id = ?", userID).Count(&emailCount).Error; err != nil {
			return err
		}
		if emailCount <= 1 {
			return ErrLastEmailCannotDelete
		}

		if emailRecord.IsPrimary {
			var anotherEmail model.UserEmail
			if err := tx.Where("user_id = ? AND id != ?", userID, emailID).First(&anotherEmail).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.UserEmail{}).Where("id = ?", anotherEmail.ID).Update("is_primary", true).Error; err != nil {
				return err
			}
		}

		return tx.Delete(&emailRecord).Error
	})
}

// VerifyEmail refreshes verification metadata for an unverified email.
func (s *CurrentUserService) VerifyEmail(ctx context.Context, input VerifyEmailInput) (*VerificationEmailView, error) {
	verificationTTL := input.VerificationTTL
	if verificationTTL <= 0 {
		verificationTTL = 24 * time.Hour
	}

	var emailRecord model.UserEmail
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ? AND user_id = ?", input.EmailID, input.UserID).First(&emailRecord).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrEmailNotFound
			}
			return err
		}
		if emailRecord.VerifiedAt.Valid {
			return ErrEmailAlreadyVerified
		}
		if time.Since(emailRecord.UpdatedAt) < time.Minute {
			return ErrEmailRateLimited
		}

		verificationToken, err := generateVerificationToken()
		if err != nil {
			return err
		}
		verificationExpiry := time.Now().UTC().Add(verificationTTL)
		emailRecord.VerificationToken = hashVerificationToken(verificationToken)
		emailRecord.VerificationExpiry = sql.NullTime{Time: verificationExpiry, Valid: true}
		if err := tx.Model(&emailRecord).Updates(map[string]any{
			"verification_token":  emailRecord.VerificationToken,
			"verification_expiry": emailRecord.VerificationExpiry,
		}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", emailRecord.ID).First(&emailRecord).Error
	})
	if err != nil {
		return nil, err
	}
	return &VerificationEmailView{VerificationExpiresAt: emailRecord.VerificationExpiry.Time.Format(time.RFC3339)}, nil
}

// ListLoginMethods returns current-user login methods.
func (s *CurrentUserService) ListLoginMethods(ctx context.Context, userID uint64) ([]LoginMethodView, error) {
	var credentials []model.UserCredential
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at ASC").Find(&credentials).Error; err != nil {
		return nil, err
	}

	var user model.User
	if err := s.db.WithContext(ctx).Select("id", "primary_login_type").First(&user, userID).Error; err != nil {
		return nil, err
	}

	return buildLoginMethodViews(user.PrimaryLoginType, credentials), nil
}

// PutLoginMethod binds a new login method for the current user.
func (s *CurrentUserService) PutLoginMethod(ctx context.Context, input PutLoginMethodInput) (*LoginMethodView, error) {
	_ = ctx
	_ = input
	return nil, ErrLoginMethodBindingUnavailable
}

// DeleteLoginMethod unbinds a login method for the current user.
func (s *CurrentUserService) DeleteLoginMethod(ctx context.Context, userID uint64, provider string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	var user model.User
	if err := s.db.WithContext(ctx).Preload("Credentials").First(&user, userID).Error; err != nil {
		return err
	}
	if err := validateDeleteLoginMethod(user.PrimaryLoginType, user.Credentials, provider); err != nil {
		return err
	}
	for i := range user.Credentials {
		if user.Credentials[i].Provider == provider {
			return s.db.WithContext(ctx).Delete(&model.UserCredential{}, user.Credentials[i].ID).Error
		}
	}
	return ErrProviderNotBound
}

func buildEmailViews(emails []model.UserEmail) []EmailView {
	views := make([]EmailView, 0, len(emails))
	for _, email := range emails {
		views = append(views, EmailView{
			ID:         email.ID,
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			VerifiedAt: nullTimePtr(email.VerifiedAt),
			CreatedAt:  email.CreatedAt,
			UpdatedAt:  email.UpdatedAt,
		})
	}
	return views
}

func buildLoginMethodViews(primary model.LoginType, credentials []model.UserCredential) []LoginMethodView {
	ordered := orderLoginMethodCredentials(credentials)
	views := make([]LoginMethodView, 0, len(ordered))
	primaryProvider := primaryLoginProvider(primary, ordered)
	for _, credential := range ordered {
		view := LoginMethodView{
			Provider:          credential.Provider,
			ProviderAccountID: credential.ProviderAccountID,
			IsPrimary:         credential.Provider == primaryProvider,
			CreatedAt:         credential.CreatedAt,
			UpdatedAt:         credential.UpdatedAt,
		}
		if credential.Metadata != "" {
			var metadata map[string]any
			if json.Unmarshal([]byte(credential.Metadata), &metadata) == nil {
				if displayName, ok := metadata["display_name"].(string); ok {
					view.DisplayName = displayName
				}
				if avatarURL, ok := metadata["avatar_url"].(string); ok {
					view.AvatarURL = avatarURL
				}
			}
		}
		views = append(views, view)
	}
	return views
}

func validateDeleteLoginMethod(primary model.LoginType, credentials []model.UserCredential, provider string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	loginMethodCount := 0
	found := false
	for i := range credentials {
		if credentials[i].Provider == provider {
			found = true
			continue
		}
		loginMethodCount++
	}
	if !found {
		return ErrProviderNotBound
	}
	if loginMethodCount == 0 {
		return ErrCannotRemoveLastLoginMethod
	}
	if primaryLoginProvider(primary, credentials) == provider {
		return ErrCannotUnbindPrimaryLogin
	}
	return nil
}

func primaryLoginProvider(primary model.LoginType, credentials []model.UserCredential) string {
	if primary == model.LoginTypeEmail {
		return string(model.LoginTypeEmail)
	}
	for _, credential := range orderLoginMethodCredentials(credentials) {
		if credential.Provider != string(model.LoginTypeEmail) {
			return credential.Provider
		}
	}
	return ""
}

func orderLoginMethodCredentials(credentials []model.UserCredential) []model.UserCredential {
	ordered := append([]model.UserCredential(nil), credentials...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			if ordered[i].ID == ordered[j].ID {
				return ordered[i].Provider < ordered[j].Provider
			}
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
	})
	return ordered
}

func primaryEmail(emails []model.UserEmail) string {
	for _, email := range emails {
		if email.IsPrimary {
			return email.Email
		}
	}
	return ""
}

func extractProviderBinding(provider string, providerData map[string]any) (string, string, string, error) {
	var providerAccountID string
	var displayName string
	var avatarURL string

	switch provider {
	case "telegram":
		if sub, ok := providerData["sub"].(string); ok {
			providerAccountID = sub
		}
		if name, ok := providerData["name"].(string); ok {
			displayName = name
		}
		if picture, ok := providerData["picture"].(string); ok {
			avatarURL = picture
		}
	case "github":
		if id, ok := providerData["id"].(float64); ok {
			providerAccountID = fmt.Sprintf("%.0f", id)
		}
		if name, ok := providerData["name"].(string); ok && name != "" {
			displayName = name
		} else if login, ok := providerData["login"].(string); ok {
			displayName = login
		}
		if avatar, ok := providerData["avatar_url"].(string); ok {
			avatarURL = avatar
		}
	default:
		return "", "", "", ErrLoginMethodInputInvalid
	}

	if providerAccountID == "" {
		return "", "", "", ErrLoginMethodInputInvalid
	}
	return providerAccountID, displayName, avatarURL, nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	copy := value.Time
	return &copy
}

func generateVerificationToken() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func hashVerificationToken(token string) string {
	if token == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
