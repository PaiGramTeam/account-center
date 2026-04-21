package platformbinding

import (
	"database/sql"
	"errors"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
)

type GrantService struct {
	db *gorm.DB
}

func NewGrantService(db *gorm.DB) *GrantService {
	return &GrantService{db: db}
}

func (s *GrantService) UpsertGrant(input UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	if err := validateConsumer(input.Consumer); err != nil {
		return nil, false, err
	}

	if err := s.ensureBindingExists(input.BindingID); err != nil {
		return nil, false, err
	}

	grantedAt := input.GrantedAt.UTC()
	if grantedAt.IsZero() {
		grantedAt = time.Now().UTC()
	}

	var grant model.ConsumerGrant
	created := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		lookup := tx.Where("binding_id = ? AND consumer = ?", input.BindingID, input.Consumer).First(&grant)
		if lookup.Error != nil {
			if !errors.Is(lookup.Error, gorm.ErrRecordNotFound) {
				return lookup.Error
			}

			grant = model.ConsumerGrant{
				BindingID: input.BindingID,
				Consumer:  input.Consumer,
				Status:    model.ConsumerGrantStatusActive,
				GrantedBy: input.GrantedBy,
				GrantedAt: grantedAt,
			}
			created = true
			return tx.Create(&grant).Error
		}

		grant.Status = model.ConsumerGrantStatusActive
		grant.GrantedBy = input.GrantedBy
		grant.GrantedAt = grantedAt
		grant.RevokedAt = sql.NullTime{}
		return tx.Save(&grant).Error
	})
	if err != nil {
		return nil, false, err
	}

	return &grant, created, nil
}

func (s *GrantService) RevokeGrant(input RevokeGrantInput) (*model.ConsumerGrant, error) {
	if err := validateConsumer(input.Consumer); err != nil {
		return nil, err
	}

	if err := s.ensureBindingExists(input.BindingID); err != nil {
		return nil, err
	}

	revokedAt := input.RevokedAt.UTC()
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	var grant model.ConsumerGrant
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("binding_id = ? AND consumer = ?", input.BindingID, input.Consumer).First(&grant).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrGrantNotFound
			}

			return err
		}

		if grant.Status == model.ConsumerGrantStatusRevoked && grant.RevokedAt.Valid {
			return nil
		}

		grant.Status = model.ConsumerGrantStatusRevoked
		grant.RevokedAt = sql.NullTime{Time: revokedAt, Valid: true}
		return tx.Save(&grant).Error
	})
	if err != nil {
		return nil, err
	}

	return &grant, nil
}

func (s *GrantService) ListGrants(bindingID uint64, params ListParams) ([]model.ConsumerGrant, int64, error) {
	params = normalizeListParams(params)

	if err := s.ensureBindingExists(bindingID); err != nil {
		return nil, 0, err
	}

	query := s.db.Model(&model.ConsumerGrant{}).Where("binding_id = ?", bindingID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var grants []model.ConsumerGrant
	if err := query.Order("id ASC").Offset(pageOffset(params)).Limit(params.PageSize).Find(&grants).Error; err != nil {
		return nil, 0, err
	}

	return grants, total, nil
}

func (s *GrantService) ListGrantsForOwner(ownerUserID, bindingID uint64, params ListParams) ([]model.ConsumerGrant, int64, error) {
	if err := s.ensureBindingOwnedByUser(ownerUserID, bindingID); err != nil {
		return nil, 0, err
	}

	return s.ListGrants(bindingID, params)
}

func (s *GrantService) UpsertGrantForOwner(ownerUserID uint64, input UpsertGrantInput) (*model.ConsumerGrant, bool, error) {
	if err := s.ensureBindingOwnedByUser(ownerUserID, input.BindingID); err != nil {
		return nil, false, err
	}

	return s.UpsertGrant(input)
}

func (s *GrantService) RevokeGrantForOwner(ownerUserID uint64, input RevokeGrantInput) (*model.ConsumerGrant, error) {
	if err := s.ensureBindingOwnedByUser(ownerUserID, input.BindingID); err != nil {
		return nil, err
	}

	return s.RevokeGrant(input)
}

func IsGrantActive(grant model.ConsumerGrant) bool {
	return grant.Status == model.ConsumerGrantStatusActive && !grant.RevokedAt.Valid
}

func (s *GrantService) ensureBindingExists(bindingID uint64) error {
	var binding model.PlatformAccountBinding
	if err := s.db.Select("id").First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBindingNotFound
		}

		return err
	}

	return nil
}

func (s *GrantService) ensureBindingOwnedByUser(ownerUserID, bindingID uint64) error {
	var binding model.PlatformAccountBinding
	if err := s.db.Select("id").Where("owner_user_id = ?", ownerUserID).First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrBindingNotFound
		}

		return err
	}

	return nil
}

func validateConsumer(consumer string) error {
	for _, supportedConsumer := range SupportedConsumers {
		if consumer == supportedConsumer {
			return nil
		}
	}

	return ErrConsumerNotSupported
}
