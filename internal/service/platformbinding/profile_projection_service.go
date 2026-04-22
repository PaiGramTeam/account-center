package platformbinding

import (
	"database/sql"
	"errors"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

type ProfileProjectionService struct {
	db *gorm.DB
}

func NewProfileProjectionService(db *gorm.DB) *ProfileProjectionService {
	return &ProfileProjectionService{db: db}
}

func (s *ProfileProjectionService) SyncProfiles(input SyncProfilesInput) ([]model.PlatformAccountProfile, error) {
	syncedAt := input.SyncedAt.UTC()
	if syncedAt.IsZero() {
		syncedAt = time.Now().UTC()
	}
	if err := validatePrimaryProfiles(input.Profiles); err != nil {
		return nil, err
	}

	profiles := make([]model.PlatformAccountProfile, 0, len(input.Profiles))
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var binding model.PlatformAccountBinding
		if err := tx.Select("id").First(&binding, input.BindingID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBindingNotFound
			}

			return err
		}

		if err := tx.Model(&model.PlatformAccountProfile{}).Where("binding_id = ?", input.BindingID).Update("is_primary", false).Error; err != nil {
			return err
		}

		primaryProfileID := sql.NullInt64{}
		profileKeys := make([]string, 0, len(input.Profiles))
		for _, item := range input.Profiles {
			profileKeys = append(profileKeys, item.PlatformProfileKey)
			var profile model.PlatformAccountProfile
			lookup := tx.Where("binding_id = ? AND platform_profile_key = ?", input.BindingID, item.PlatformProfileKey).First(&profile)
			if lookup.Error != nil {
				if !errors.Is(lookup.Error, gorm.ErrRecordNotFound) {
					return lookup.Error
				}

				profile = model.PlatformAccountProfile{
					BindingID:          input.BindingID,
					PlatformProfileKey: item.PlatformProfileKey,
				}
			}

			profile.GameBiz = item.GameBiz
			profile.Region = item.Region
			profile.PlayerUID = item.PlayerUID
			profile.Nickname = item.Nickname
			profile.Level = item.Level
			profile.IsPrimary = item.IsPrimary
			profile.SourceUpdatedAt = item.SourceUpdatedAt

			if profile.ID == 0 {
				if err := tx.Create(&profile).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Save(&profile).Error; err != nil {
					return err
				}
			}

			if profile.IsPrimary {
				primaryProfileID = sql.NullInt64{Int64: int64(profile.ID), Valid: true}
			}

			profiles = append(profiles, profile)
		}

		deleteQuery := tx.Where("binding_id = ?", input.BindingID)
		if len(profileKeys) > 0 {
			deleteQuery = deleteQuery.Where("platform_profile_key NOT IN ?", profileKeys)
		}
		if err := deleteQuery.Delete(&model.PlatformAccountProfile{}).Error; err != nil {
			return err
		}

		return tx.Model(&model.PlatformAccountBinding{}).
			Where("id = ?", input.BindingID).
			Update("primary_profile_id", nullablePrimaryProfileUpdate(primaryProfileID)).Error
	})
	if err != nil {
		return nil, err
	}

	return profiles, nil
}

func (s *ProfileProjectionService) ListProfiles(bindingID uint64, params ListParams) ([]model.PlatformAccountProfile, int64, error) {
	params = normalizeListParams(params)

	var binding model.PlatformAccountBinding
	if err := s.db.Select("id").First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrBindingNotFound
		}

		return nil, 0, err
	}

	query := s.db.Model(&model.PlatformAccountProfile{}).Where("binding_id = ?", bindingID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var profiles []model.PlatformAccountProfile
	if err := query.Order("is_primary DESC").Order("id ASC").Offset(pageOffset(params)).Limit(params.PageSize).Find(&profiles).Error; err != nil {
		return nil, 0, err
	}

	return profiles, total, nil
}

func (s *ProfileProjectionService) ListProfilesForOwner(ownerUserID, bindingID uint64, params ListParams) ([]model.PlatformAccountProfile, int64, error) {
	var binding model.PlatformAccountBinding
	if err := s.db.Select("id").Where("owner_user_id = ?", ownerUserID).First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrBindingNotFound
		}

		return nil, 0, err
	}

	return s.ListProfiles(bindingID, params)
}

func (s *ProfileProjectionService) DeleteProfiles(bindingID uint64) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var binding model.PlatformAccountBinding
		if err := tx.Select("id").First(&binding, bindingID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBindingNotFound
			}

			return err
		}

		if err := tx.Model(&model.PlatformAccountBinding{}).Where("id = ?", bindingID).Update("primary_profile_id", nil).Error; err != nil {
			return err
		}

		return tx.Where("binding_id = ?", bindingID).Delete(&model.PlatformAccountProfile{}).Error
	})
}

func (s *ProfileProjectionService) GetProfile(bindingID, profileID uint64) (*model.PlatformAccountProfile, error) {
	var profile model.PlatformAccountProfile
	if err := s.db.Where("binding_id = ?", bindingID).First(&profile, profileID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPrimaryProfileNotOwned
		}
		return nil, err
	}

	return &profile, nil
}

func (s *ProfileProjectionService) SetPrimaryProfileForOwner(ownerUserID, bindingID uint64, profileID *uint64) (*model.PlatformAccountBinding, error) {
	var updated model.PlatformAccountBinding
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var binding model.PlatformAccountBinding
		if err := tx.Where("owner_user_id = ?", ownerUserID).First(&binding, bindingID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBindingNotFound
			}
			return err
		}

		if err := tx.Model(&model.PlatformAccountProfile{}).Where("binding_id = ?", binding.ID).Update("is_primary", false).Error; err != nil {
			return err
		}

		binding.PrimaryProfileID = sql.NullInt64{}
		if profileID != nil && *profileID != 0 {
			var profile model.PlatformAccountProfile
			if err := tx.Where("binding_id = ?", binding.ID).First(&profile, *profileID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrPrimaryProfileNotOwned
				}
				return err
			}
			if err := tx.Model(&model.PlatformAccountProfile{}).Where("id = ?", profile.ID).Update("is_primary", true).Error; err != nil {
				return err
			}
			binding.PrimaryProfileID = sql.NullInt64{Int64: int64(profile.ID), Valid: true}
		}

		if err := tx.Model(&model.PlatformAccountBinding{}).Where("id = ?", binding.ID).Update("primary_profile_id", nullablePrimaryProfileUpdate(binding.PrimaryProfileID)).Error; err != nil {
			return err
		}

		updated = binding
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &updated, nil
}

func validatePrimaryProfiles(profiles []ProfileProjectionInput) error {
	primaryCount := 0
	for _, profile := range profiles {
		if profile.IsPrimary {
			primaryCount++
		}
		if primaryCount > 1 {
			return ErrMultiplePrimaryProfiles
		}
	}

	return nil
}

func nullablePrimaryProfileUpdate(primaryProfileID sql.NullInt64) any {
	if !primaryProfileID.Valid {
		return nil
	}
	return primaryProfileID.Int64
}
