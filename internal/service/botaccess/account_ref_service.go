package botaccess

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

type AccountRefService struct {
	db *gorm.DB
}

type LinkPlatformAccountParams struct {
	BotID              string
	ExternalUserID     string
	Platform           string
	PlatformServiceKey string
	PlatformAccountID  string
	DisplayName        string
	MetaJSON           string
	GrantScopes        []string
}

func (s *AccountRefService) ResolveBotUser(botID, externalUserID string) (*model.BotIdentity, error) {
	var identity model.BotIdentity
	if err := s.db.Where("bot_id = ? AND external_user_id = ?", botID, externalUserID).First(&identity).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrBotIdentityNotFound
		}
		return nil, fmt.Errorf("resolve bot user: %w", err)
	}

	return &identity, nil
}

func (s *AccountRefService) LinkPlatformAccount(params LinkPlatformAccountParams) (*model.PlatformAccountRef, bool, error) {
	identity, err := s.ResolveBotUser(params.BotID, params.ExternalUserID)
	if err != nil {
		return nil, false, err
	}

	scopeJSON, err := json.Marshal(params.GrantScopes)
	if err != nil {
		return nil, false, fmt.Errorf("link platform account: marshal scopes: %w", err)
	}

	created := false
	var ref model.PlatformAccountRef
	err = s.db.Transaction(func(tx *gorm.DB) error {
		lookup := tx.Where("platform = ? AND platform_account_id = ?", params.Platform, params.PlatformAccountID).First(&ref)
		if lookup.Error != nil {
			if lookup.Error != gorm.ErrRecordNotFound {
				return lookup.Error
			}

			ref = model.PlatformAccountRef{
				UserID:             identity.UserID,
				Platform:           params.Platform,
				PlatformServiceKey: params.PlatformServiceKey,
				PlatformAccountID:  params.PlatformAccountID,
				DisplayName:        params.DisplayName,
				Status:             model.PlatformAccountRefStatusActive,
				MetaJSON:           nullString(params.MetaJSON),
			}
			if err := tx.Create(&ref).Error; err != nil {
				return err
			}
			created = true
		} else {
			if ref.UserID != identity.UserID {
				return ErrPlatformAccountOwnedByOtherUser
			}
			ref.PlatformServiceKey = params.PlatformServiceKey
			ref.DisplayName = params.DisplayName
			ref.Status = model.PlatformAccountRefStatusActive
			ref.MetaJSON = nullString(params.MetaJSON)
			if err := tx.Save(&ref).Error; err != nil {
				return err
			}
		}

		var grant model.BotAccountGrant
		grantLookup := tx.Where("bot_id = ? AND platform_account_ref_id = ?", params.BotID, ref.ID).First(&grant)
		if grantLookup.Error != nil {
			if grantLookup.Error != gorm.ErrRecordNotFound {
				return grantLookup.Error
			}

			grant = model.BotAccountGrant{
				UserID:               identity.UserID,
				BotID:                params.BotID,
				PlatformAccountRefID: ref.ID,
				Scopes:               string(scopeJSON),
				GrantedAt:            time.Now().UTC(),
			}
			return tx.Create(&grant).Error
		}

		grant.UserID = identity.UserID
		grant.Scopes = string(scopeJSON)
		grant.RevokedAt = sql.NullTime{}
		return tx.Save(&grant).Error
	})
	if err != nil {
		return nil, false, fmt.Errorf("link platform account: %w", err)
	}

	return &ref, created, nil
}

func (s *AccountRefService) ListAccessibleAccounts(botID, externalUserID, platform string) ([]model.PlatformAccountRef, error) {
	identity, err := s.ResolveBotUser(botID, externalUserID)
	if err != nil {
		return nil, err
	}
	consumer := consumerName(botID)
	if consumer == "" {
		return []model.PlatformAccountRef{}, nil
	}

	query := s.db.Model(&model.PlatformAccountBinding{}).
		Joins("JOIN consumer_grants ON consumer_grants.binding_id = platform_account_bindings.id").
		Where("platform_account_bindings.owner_user_id = ?", identity.UserID).
		Where("consumer_grants.consumer = ?", consumer).
		Where("consumer_grants.status = ?", model.ConsumerGrantStatusActive).
		Where("consumer_grants.revoked_at IS NULL").
		Where("platform_account_bindings.status = ?", model.PlatformAccountBindingStatusActive)

	if platform != "" {
		query = query.Where("platform_account_bindings.platform = ?", platform)
	}

	var bindings []model.PlatformAccountBinding
	if err := query.Order("platform_account_bindings.created_at ASC").Find(&bindings).Error; err != nil {
		return nil, fmt.Errorf("list accessible accounts: %w", err)
	}

	refs := make([]model.PlatformAccountRef, 0, len(bindings))
	for _, binding := range bindings {
		refs = append(refs, bindingToPlatformAccountRef(binding))
	}

	return refs, nil
}

func (s *AccountRefService) GetGrantedBinding(botID, externalUserID string, bindingID, profileID uint64) (*model.BotIdentity, *model.PlatformAccountBinding, *model.ConsumerGrant, error) {
	identity, err := s.ResolveBotUser(botID, externalUserID)
	if err != nil {
		return nil, nil, nil, err
	}
	consumer := consumerName(botID)
	if consumer == "" {
		return nil, nil, nil, ErrBotGrantNotFound
	}

	var binding model.PlatformAccountBinding
	if err := s.db.Where("id = ? AND owner_user_id = ?", bindingID, identity.UserID).First(&binding).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrPlatformAccountMissing
		}
		return nil, nil, nil, fmt.Errorf("get platform account binding: %w", err)
	}
	if binding.Status != model.PlatformAccountBindingStatusActive {
		return nil, nil, nil, ErrInactiveAccountRef
	}

	var grant model.ConsumerGrant
	if err := s.db.Where("binding_id = ? AND consumer = ?", binding.ID, consumer).First(&grant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrBotGrantNotFound
		}
		return nil, nil, nil, fmt.Errorf("get consumer grant: %w", err)
	}
	if grant.Status != model.ConsumerGrantStatusActive || grant.RevokedAt.Valid {
		return nil, nil, nil, ErrBotGrantRevoked
	}
	if profileID != 0 {
		var profile model.PlatformAccountProfile
		if err := s.db.Where("binding_id = ?", binding.ID).First(&profile, profileID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, nil, nil, ErrPlatformAccountMissing
			}
			return nil, nil, nil, fmt.Errorf("get platform account profile: %w", err)
		}
	}

	return identity, &binding, &grant, nil
}

func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: value, Valid: true}
}

func consumerName(botID string) string {
	switch botID {
	case "bot-paigram", "paigram-bot":
		return "paigram-bot"
	default:
		return ""
	}
}

func bindingToPlatformAccountRef(binding model.PlatformAccountBinding) model.PlatformAccountRef {
	return model.PlatformAccountRef{
		ID:                 binding.ID,
		UserID:             binding.OwnerUserID,
		Platform:           binding.Platform,
		PlatformServiceKey: binding.PlatformServiceKey,
		PlatformAccountID:  nullableBindingExternalAccountKey(binding.ExternalAccountKey),
		DisplayName:        binding.DisplayName,
		Status:             bindingStatusToLegacyStatus(binding.Status),
		CreatedAt:          binding.CreatedAt,
		UpdatedAt:          binding.UpdatedAt,
	}
}

func bindingStatusToLegacyStatus(status model.PlatformAccountBindingStatus) model.PlatformAccountRefStatus {
	switch status {
	case model.PlatformAccountBindingStatusActive:
		return model.PlatformAccountRefStatusActive
	case model.PlatformAccountBindingStatusDeleted, model.PlatformAccountBindingStatusDeleting:
		return model.PlatformAccountRefStatusRevoked
	default:
		return model.PlatformAccountRefStatusInactive
	}
}

func nullableBindingExternalAccountKey(value sql.NullString) string {
	if !value.Valid {
		return ""
	}

	return value.String
}
