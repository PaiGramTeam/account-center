package platformbinding

import (
	"errors"

	mysql "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"paigram/internal/model"
)

type UpdateBindingInput struct {
	DisplayName        *string
	PlatformServiceKey *string
}

type BindingService struct {
	db *gorm.DB
}

func NewBindingService(db *gorm.DB) *BindingService {
	return &BindingService{db: db}
}

func (s *BindingService) CreateBinding(input CreateBindingInput) (*model.PlatformAccountBinding, error) {
	var existing model.PlatformAccountBinding
	err := s.db.Where("platform = ? AND external_account_key = ?", input.Platform, input.ExternalAccountKey).First(&existing).Error
	if err == nil {
		if existing.OwnerUserID != input.OwnerUserID {
			return nil, ErrBindingAlreadyOwned
		}

		return &existing, nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	binding := &model.PlatformAccountBinding{
		OwnerUserID:        input.OwnerUserID,
		Platform:           input.Platform,
		ExternalAccountKey: input.ExternalAccountKey,
		PlatformServiceKey: input.PlatformServiceKey,
		DisplayName:        input.DisplayName,
		Status:             model.PlatformAccountBindingStatusPendingBind,
	}
	if err := s.db.Create(binding).Error; err != nil {
		return s.handleCreateBindingError(err, input)
	}

	return binding, nil
}

func (s *BindingService) UpdateBinding(bindingID uint64, input UpdateBindingInput) (*model.PlatformAccountBinding, error) {
	binding, err := s.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}

	return s.updateBinding(binding, input)
}

func (s *BindingService) UpdateBindingForOwner(ownerUserID, bindingID uint64, input UpdateBindingInput) (*model.PlatformAccountBinding, error) {
	binding, err := s.GetBindingForOwner(ownerUserID, bindingID)
	if err != nil {
		return nil, err
	}

	return s.updateBinding(binding, input)
}

func (s *BindingService) GetBindingByID(bindingID uint64) (*model.PlatformAccountBinding, error) {
	var binding model.PlatformAccountBinding
	if err := s.db.First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrBindingNotFound
		}

		return nil, err
	}

	return &binding, nil
}

func (s *BindingService) GetBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	var binding model.PlatformAccountBinding
	if err := s.db.Where("owner_user_id = ?", ownerUserID).First(&binding, bindingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrBindingNotFound
		}

		return nil, err
	}

	return &binding, nil
}

func (s *BindingService) DeleteBindingForOwner(ownerUserID, bindingID uint64) (*model.PlatformAccountBinding, error) {
	if _, err := s.GetBindingForOwner(ownerUserID, bindingID); err != nil {
		return nil, err
	}

	return s.DeleteBinding(bindingID)
}

func (s *BindingService) ListBindings() ([]model.PlatformAccountBinding, error) {
	var bindings []model.PlatformAccountBinding
	if err := s.db.Order("id ASC").Find(&bindings).Error; err != nil {
		return nil, err
	}

	return bindings, nil
}

func (s *BindingService) ListBindingsByOwner(ownerUserID uint64) ([]model.PlatformAccountBinding, error) {
	var bindings []model.PlatformAccountBinding
	if err := s.db.Where("owner_user_id = ?", ownerUserID).Order("id ASC").Find(&bindings).Error; err != nil {
		return nil, err
	}

	return bindings, nil
}

func (s *BindingService) UpdateBindingStatus(bindingID uint64, status model.PlatformAccountBindingStatus) (*model.PlatformAccountBinding, error) {
	binding, err := s.GetBindingByID(bindingID)
	if err != nil {
		return nil, err
	}

	binding.Status = status
	if err := s.db.Save(binding).Error; err != nil {
		return nil, err
	}

	return binding, nil
}

func (s *BindingService) RefreshBinding(bindingID uint64) (*model.PlatformAccountBinding, error) {
	return s.UpdateBindingStatus(bindingID, model.PlatformAccountBindingStatusRefreshRequired)
}

func (s *BindingService) DeleteBinding(bindingID uint64) (*model.PlatformAccountBinding, error) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var binding model.PlatformAccountBinding
		if err := tx.First(&binding, bindingID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBindingNotFound
			}

			return err
		}

		binding.Status = model.PlatformAccountBindingStatusDeleted
		if err := tx.Save(&binding).Error; err != nil {
			return err
		}

		return tx.Delete(&binding).Error
	})
	if err != nil {
		return nil, err
	}

	var binding model.PlatformAccountBinding
	if err := s.db.Unscoped().First(&binding, bindingID).Error; err != nil {
		return nil, err
	}

	return &binding, nil
}

func (s *BindingService) updateBinding(binding *model.PlatformAccountBinding, input UpdateBindingInput) (*model.PlatformAccountBinding, error) {
	updates := map[string]any{}
	if input.DisplayName != nil {
		updates["display_name"] = *input.DisplayName
		binding.DisplayName = *input.DisplayName
	}
	if input.PlatformServiceKey != nil {
		updates["platform_service_key"] = *input.PlatformServiceKey
		binding.PlatformServiceKey = *input.PlatformServiceKey
	}
	if len(updates) == 0 {
		return binding, nil
	}

	if err := s.db.Model(&model.PlatformAccountBinding{}).Where("id = ?", binding.ID).Updates(updates).Error; err != nil {
		return nil, err
	}

	if err := s.db.First(binding, binding.ID).Error; err != nil {
		return nil, err
	}

	return binding, nil
}

func (s *BindingService) handleCreateBindingError(err error, input CreateBindingInput) (*model.PlatformAccountBinding, error) {
	if !isDuplicateBindingError(err) {
		return nil, err
	}

	var existing model.PlatformAccountBinding
	lookupErr := s.db.Where("platform = ? AND external_account_key = ?", input.Platform, input.ExternalAccountKey).First(&existing).Error
	if lookupErr != nil {
		return nil, ErrBindingAlreadyOwned
	}
	if existing.OwnerUserID != input.OwnerUserID {
		return nil, ErrBindingAlreadyOwned
	}
	return &existing, nil
}

func isDuplicateBindingError(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}

	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}
