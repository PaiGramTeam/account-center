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

	query := s.db.Model(&model.PlatformAccountRef{}).
		Joins("JOIN bot_account_grants ON bot_account_grants.platform_account_ref_id = platform_account_refs.id").
		Where("platform_account_refs.user_id = ?", identity.UserID).
		Where("bot_account_grants.bot_id = ?", botID).
		Where("bot_account_grants.revoked_at IS NULL").
		Where("platform_account_refs.status = ?", model.PlatformAccountRefStatusActive)

	if platform != "" {
		query = query.Where("platform_account_refs.platform = ?", platform)
	}

	var refs []model.PlatformAccountRef
	if err := query.Order("platform_account_refs.created_at ASC").Find(&refs).Error; err != nil {
		return nil, fmt.Errorf("list accessible accounts: %w", err)
	}

	return refs, nil
}

func (s *AccountRefService) GetGrantedAccount(botID, externalUserID string, platformAccountRefID uint64) (*model.BotIdentity, *model.PlatformAccountRef, *model.BotAccountGrant, error) {
	identity, err := s.ResolveBotUser(botID, externalUserID)
	if err != nil {
		return nil, nil, nil, err
	}

	var ref model.PlatformAccountRef
	if err := s.db.Where("id = ? AND user_id = ?", platformAccountRefID, identity.UserID).First(&ref).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrPlatformAccountMissing
		}
		return nil, nil, nil, fmt.Errorf("get platform account ref: %w", err)
	}

	var grant model.BotAccountGrant
	if err := s.db.Where("bot_id = ? AND platform_account_ref_id = ?", botID, ref.ID).First(&grant).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil, nil, ErrBotGrantNotFound
		}
		return nil, nil, nil, fmt.Errorf("get bot account grant: %w", err)
	}
	if grant.RevokedAt.Valid {
		return nil, nil, nil, ErrBotGrantRevoked
	}

	return identity, &ref, &grant, nil
}

func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: value, Valid: true}
}
