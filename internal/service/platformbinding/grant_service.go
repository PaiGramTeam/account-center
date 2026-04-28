package platformbinding

import (
	"database/sql"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
	serviceaudit "paigram/internal/service/audit"
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

	binding, err := s.getBinding(input.BindingID)
	if err != nil {
		return nil, false, err
	}

	grantedAt := input.GrantedAt.UTC()
	if grantedAt.IsZero() {
		grantedAt = time.Now().UTC()
	}

	var grant model.ConsumerGrant
	created := false
	err = s.db.Transaction(func(tx *gorm.DB) error {
		lookup := tx.Where("binding_id = ? AND consumer = ?", input.BindingID, input.Consumer).First(&grant)
		if lookup.Error != nil {
			if !errors.Is(lookup.Error, gorm.ErrRecordNotFound) {
				return lookup.Error
			}

			grant = model.ConsumerGrant{
				BindingID: input.BindingID,
				Consumer:  input.Consumer,
				Status:    model.ConsumerGrantStatusActive,
				ScopesJSON: "[]",
				GrantedBy: input.GrantedBy,
				GrantedAt: grantedAt,
			}
			created = true
			if err := tx.Create(&grant).Error; err != nil {
				return err
			}
			return writeGrantAudit(tx, binding, input.BindingID, input.Consumer, auditActorUserID(input.GrantedBy), true, created)
		}

		grant.Status = model.ConsumerGrantStatusActive
		grant.GrantedBy = input.GrantedBy
		grant.GrantedAt = grantedAt
		grant.RevokedAt = sql.NullTime{}
		if err := tx.Save(&grant).Error; err != nil {
			return err
		}
		return writeGrantAudit(tx, binding, input.BindingID, input.Consumer, auditActorUserID(input.GrantedBy), true, created)
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

	binding, err := s.getBinding(input.BindingID)
	if err != nil {
		return nil, err
	}

	revokedAt := input.RevokedAt.UTC()
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	var grant model.ConsumerGrant
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("binding_id = ? AND consumer = ?", input.BindingID, input.Consumer).First(&grant).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				grant = model.ConsumerGrant{
					BindingID: input.BindingID,
					Consumer:  input.Consumer,
					Status:    model.ConsumerGrantStatusRevoked,
					RevokedAt: sql.NullTime{Time: revokedAt, Valid: true},
				}
				return writeGrantAudit(tx, binding, input.BindingID, input.Consumer, auditActorUserID(input.ActorUserID), false, true)
			}

			return err
		}

		if grant.Status == model.ConsumerGrantStatusRevoked && grant.RevokedAt.Valid {
			return writeGrantAudit(tx, binding, input.BindingID, input.Consumer, auditActorUserID(input.ActorUserID), false, true)
		}

		grant.Status = model.ConsumerGrantStatusRevoked
		grant.RevokedAt = sql.NullTime{Time: revokedAt, Valid: true}
		if err := tx.Save(&grant).Error; err != nil {
			return err
		}
		return writeGrantAudit(tx, binding, input.BindingID, input.Consumer, auditActorUserID(input.ActorUserID), false, false)
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

func (s *GrantService) DeleteGrants(bindingID uint64) error {
	if err := s.ensureBindingExists(bindingID); err != nil {
		return err
	}

	return s.db.Where("binding_id = ?", bindingID).Delete(&model.ConsumerGrant{}).Error
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
	_, err := s.getBinding(bindingID)
	return err
}

func (s *GrantService) getBinding(bindingID uint64) (*model.PlatformAccountBinding, error) {
	var binding model.PlatformAccountBinding
	if err := s.db.Select("id", "owner_user_id").First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrBindingNotFound
		}

		return nil, err
	}

	return &binding, nil
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

func writeGrantAudit(tx *gorm.DB, binding *model.PlatformAccountBinding, bindingID uint64, consumer string, actorUserID *uint64, enabled bool, idempotent bool) error {
	ownerUserID := uint64(0)
	if binding != nil {
		ownerUserID = binding.OwnerUserID
	}
	actorType := "user"
	if actorUserID != nil && ownerUserID != 0 && *actorUserID != ownerUserID {
		actorType = "admin"
	}
	return serviceaudit.RecordTx(tx, serviceaudit.WriteInput{
		Category:    "platform_binding",
		ActorType:   actorType,
		ActorUserID: actorUserID,
		Action:      "grant_change",
		TargetType:  "binding",
		TargetID:    strconv.FormatUint(bindingID, 10),
		BindingID:   &bindingID,
		OwnerUserID: zeroableUint64(ownerUserID),
		Result:      "success",
		Metadata: map[string]any{
			"consumer":      consumer,
			"grant_enabled": enabled,
			"idempotent":    idempotent,
		},
	})
}

func auditActorUserID(value sql.NullInt64) *uint64 {
	if !value.Valid || value.Int64 <= 0 {
		return nil
	}
	converted := uint64(value.Int64)
	return &converted
}

func zeroableUint64(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	return &value
}
