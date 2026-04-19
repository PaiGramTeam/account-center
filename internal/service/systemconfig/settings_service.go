package systemconfig

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

const (
	DomainSite         = "site"
	DomainRegistration = "registration"
	DomainEmail        = "email"
	DomainAuthControls = "auth_controls"
)

// SettingsView is the admin API projection for one grouped settings domain.
type SettingsView struct {
	Domain    string         `json:"domain"`
	Settings  map[string]any `json:"settings"`
	Version   uint64         `json:"version"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
}

// SettingsService persists grouped system settings.
type SettingsService struct {
	db *gorm.DB
}

const maxPatchRetries = 3

var errSettingsWriteConflict = errors.New("system settings write conflict")

// NewSettingsService creates a grouped settings service.
func NewSettingsService(db *gorm.DB) *SettingsService {
	return &SettingsService{db: db}
}

func (s *SettingsService) GetSite(ctx context.Context) (*SettingsView, error) {
	return s.getDomain(ctx, DomainSite)
}

func (s *SettingsService) PatchSite(ctx context.Context, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	return s.patchDomain(ctx, DomainSite, patch, actorUserID)
}

func (s *SettingsService) GetRegistration(ctx context.Context) (*SettingsView, error) {
	return s.getDomain(ctx, DomainRegistration)
}

func (s *SettingsService) PatchRegistration(ctx context.Context, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	return s.patchDomain(ctx, DomainRegistration, patch, actorUserID)
}

func (s *SettingsService) GetEmail(ctx context.Context) (*SettingsView, error) {
	return s.getDomain(ctx, DomainEmail)
}

func (s *SettingsService) PatchEmail(ctx context.Context, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	return s.patchDomain(ctx, DomainEmail, patch, actorUserID)
}

func (s *SettingsService) GetAuthControls(ctx context.Context) (*SettingsView, error) {
	return s.getDomain(ctx, DomainAuthControls)
}

func (s *SettingsService) PatchAuthControls(ctx context.Context, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	return s.patchDomain(ctx, DomainAuthControls, patch, actorUserID)
}

func (s *SettingsService) getDomain(ctx context.Context, domain string) (*SettingsView, error) {
	if !isAllowedDomain(domain) {
		return nil, ErrInvalidSettingsDomain
	}

	var entry model.SystemConfigEntry
	err := s.db.WithContext(ctx).Where("config_domain = ?", domain).First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &SettingsView{Domain: domain, Settings: map[string]any{}}, nil
	}
	if err != nil {
		return nil, err
	}

	settings, err := decodeSettingsPayload(entry.PayloadJSON)
	if err != nil {
		return nil, err
	}

	return &SettingsView{
		Domain:    domain,
		Settings:  settings,
		Version:   entry.Version,
		UpdatedAt: entry.UpdatedAt,
	}, nil
}

func (s *SettingsService) patchDomain(ctx context.Context, domain string, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	if !isAllowedDomain(domain) {
		return nil, ErrInvalidSettingsDomain
	}
	if patch == nil {
		patch = map[string]any{}
	}
	patch = cloneSettings(patch)

	for attempt := 0; attempt < maxPatchRetries; attempt++ {
		view, err := s.patchDomainOnce(ctx, domain, patch, actorUserID)
		if errors.Is(err, errSettingsWriteConflict) {
			continue
		}
		return view, err
	}

	return nil, errSettingsWriteConflict
}

func (s *SettingsService) patchDomainOnce(ctx context.Context, domain string, patch map[string]any, actorUserID uint64) (*SettingsView, error) {
	var result model.SystemConfigEntry
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var entry model.SystemConfigEntry
		err := tx.Where("config_domain = ?", domain).First(&entry).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		settings := map[string]any{}
		if err == nil {
			decoded, decodeErr := decodeSettingsPayload(entry.PayloadJSON)
			if decodeErr != nil {
				return decodeErr
			}
			settings = decoded
		}
		mergeSettings(settings, patch)
		payloadJSON, marshalErr := json.Marshal(settings)
		if marshalErr != nil {
			return marshalErr
		}

		entry.ConfigDomain = domain
		entry.PayloadJSON = string(payloadJSON)
		entry.UpdatedBy = nullableUserID(actorUserID)
		if entry.ID == 0 {
			entry.Version = 1
			if createErr := tx.Create(&entry).Error; createErr != nil {
				if isSettingsConflict(createErr) {
					return errSettingsWriteConflict
				}
				return createErr
			}
		} else {
			currentVersion := entry.Version
			entry.Version++
			entry.UpdatedAt = time.Now().UTC()
			updateResult := tx.Model(&model.SystemConfigEntry{}).
				Where("id = ? AND version = ?", entry.ID, currentVersion).
				Updates(map[string]any{
					"payload_json": entry.PayloadJSON,
					"version":      entry.Version,
					"updated_by":   entry.UpdatedBy,
					"updated_at":   entry.UpdatedAt,
				})
			if updateResult.Error != nil {
				return updateResult.Error
			}
			if updateResult.RowsAffected == 0 {
				return errSettingsWriteConflict
			}
		}

		metadataJSON, metadataErr := json.Marshal(buildSettingsAuditMetadata(domain, patch))
		if metadataErr != nil {
			return metadataErr
		}
		if auditErr := tx.Create(&model.AuditEvent{
			Category:     "system_settings",
			ActorType:    "user",
			ActorUserID:  nullableUserID(actorUserID),
			Action:       "updated",
			TargetType:   "system_config_entry",
			TargetID:     domain,
			Result:       "success",
			MetadataJSON: string(metadataJSON),
			CreatedAt:    time.Now().UTC(),
		}).Error; auditErr != nil {
			return auditErr
		}

		result = entry
		return nil
	})
	if err != nil {
		return nil, err
	}

	settings, err := decodeSettingsPayload(result.PayloadJSON)
	if err != nil {
		return nil, err
	}

	return &SettingsView{
		Domain:    result.ConfigDomain,
		Settings:  settings,
		Version:   result.Version,
		UpdatedAt: result.UpdatedAt,
	}, nil
}

func isAllowedDomain(domain string) bool {
	switch strings.TrimSpace(domain) {
	case DomainSite, DomainRegistration, DomainEmail, DomainAuthControls:
		return true
	default:
		return false
	}
}

func decodeSettingsPayload(payload string) (map[string]any, error) {
	if strings.TrimSpace(payload) == "" {
		return map[string]any{}, nil
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(payload), &settings); err != nil {
		return nil, err
	}
	if settings == nil {
		settings = map[string]any{}
	}
	return settings, nil
}

func mergeSettings(dst map[string]any, patch map[string]any) {
	for key, value := range patch {
		dst[key] = value
	}
}

func cloneSettings(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func buildSettingsAuditMetadata(domain string, patch map[string]any) map[string]any {
	changedKeys := make([]string, 0, len(patch))
	for key := range patch {
		changedKeys = append(changedKeys, key)
	}
	sort.Strings(changedKeys)

	return map[string]any{
		"domain":       domain,
		"changed_keys": changedKeys,
	}
}

func isSettingsConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "duplicate entry") || strings.Contains(errText, "duplicated key") || strings.Contains(errText, "unique constraint failed")
}

func nullableUserID(userID uint64) sql.NullInt64 {
	if userID == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(userID), Valid: true}
}
