package user

import (
	"database/sql"
	"errors"

	"gorm.io/gorm"

	"paigram/internal/model"
)

func (s *UserService) ReplaceUserRoles(userID uint64, roleIDs []uint64, primaryRoleID *uint64, grantedBy uint64) (*model.User, error) {
	normalizedRoleIDs := normalizeRoleIDs(roleIDs)

	var updated model.User
	err := s.db.Transaction(func(tx *gorm.DB) error {
		user, err := loadUserForRoleMutation(tx, userID)
		if err != nil {
			return err
		}

		if err := ensureRolesExist(tx, normalizedRoleIDs); err != nil {
			return err
		}

		desiredPrimary, err := resolvePrimaryRole(user.PrimaryRoleID, normalizedRoleIDs, primaryRoleID)
		if err != nil {
			return err
		}

		var existingAssignments []model.UserRole
		if err := tx.Where("user_id = ?", userID).Find(&existingAssignments).Error; err != nil {
			return err
		}

		existingByRoleID := make(map[uint64]model.UserRole, len(existingAssignments))
		for _, assignment := range existingAssignments {
			existingByRoleID[assignment.RoleID] = assignment
		}

		desiredRoleIDs := make(map[uint64]struct{}, len(normalizedRoleIDs))
		for _, roleID := range normalizedRoleIDs {
			desiredRoleIDs[roleID] = struct{}{}
		}

		removedRoleIDs := make([]uint64, 0)
		for _, assignment := range existingAssignments {
			if _, keep := desiredRoleIDs[assignment.RoleID]; keep {
				continue
			}
			removedRoleIDs = append(removedRoleIDs, assignment.RoleID)
		}
		if len(removedRoleIDs) > 0 {
			if err := tx.Where("user_id = ? AND role_id IN ?", userID, removedRoleIDs).Delete(&model.UserRole{}).Error; err != nil {
				return err
			}
		}

		for _, roleID := range normalizedRoleIDs {
			if _, exists := existingByRoleID[roleID]; exists {
				continue
			}
			if err := tx.Create(&model.UserRole{UserID: userID, RoleID: roleID, GrantedBy: grantedBy}).Error; err != nil {
				return err
			}
		}

		user.PrimaryRoleID = desiredPrimary
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Update("primary_role_id", nullablePrimaryRoleUpdate(desiredPrimary)).Error; err != nil {
			return err
		}

		updated = *user
		updated.PrimaryRoleID = desiredPrimary
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &updated, nil
}

func (s *UserService) SetPrimaryRole(userID uint64, primaryRoleID *uint64, clear bool) (*model.User, error) {
	var updated model.User
	err := s.db.Transaction(func(tx *gorm.DB) error {
		user, err := loadUserForRoleMutation(tx, userID)
		if err != nil {
			return err
		}

		roleIDs, err := currentRoleIDs(tx, userID)
		if err != nil {
			return err
		}

		if clear {
			user.PrimaryRoleID = sql.NullInt64{}
			if err := tx.Model(&model.User{}).Where("id = ?", userID).Update("primary_role_id", nil).Error; err != nil {
				return err
			}
			updated = *user
			return nil
		}

		desiredPrimary, err := resolvePrimaryRole(user.PrimaryRoleID, roleIDs, primaryRoleID)
		if err != nil {
			return err
		}

		user.PrimaryRoleID = desiredPrimary
		if err := tx.Model(&model.User{}).Where("id = ?", userID).Update("primary_role_id", nullablePrimaryRoleUpdate(desiredPrimary)).Error; err != nil {
			return err
		}

		updated = *user
		updated.PrimaryRoleID = desiredPrimary
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &updated, nil
}

func loadUserForRoleMutation(tx *gorm.DB, userID uint64) (*model.User, error) {
	var user model.User
	if err := tx.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func ensureRolesExist(tx *gorm.DB, roleIDs []uint64) error {
	if len(roleIDs) == 0 {
		return nil
	}

	var count int64
	if err := tx.Model(&model.Role{}).Where("id IN ?", roleIDs).Count(&count).Error; err != nil {
		return err
	}
	if count != int64(len(roleIDs)) {
		return ErrRoleNotFound
	}
	return nil
}

func currentRoleIDs(tx *gorm.DB, userID uint64) ([]uint64, error) {
	var assignments []model.UserRole
	if err := tx.Where("user_id = ?", userID).Find(&assignments).Error; err != nil {
		return nil, err
	}
	roleIDs := make([]uint64, 0, len(assignments))
	for _, assignment := range assignments {
		roleIDs = append(roleIDs, assignment.RoleID)
	}
	return roleIDs, nil
}

func resolvePrimaryRole(currentPrimary sql.NullInt64, roleIDs []uint64, requestedPrimaryRoleID *uint64) (sql.NullInt64, error) {
	if requestedPrimaryRoleID != nil {
		if *requestedPrimaryRoleID == 0 {
			return sql.NullInt64{}, nil
		}
		if !containsRoleID(roleIDs, *requestedPrimaryRoleID) {
			return sql.NullInt64{}, ErrPrimaryRoleNotAssigned
		}
		return sql.NullInt64{Int64: int64(*requestedPrimaryRoleID), Valid: true}, nil
	}

	if currentPrimary.Valid && containsRoleID(roleIDs, uint64(currentPrimary.Int64)) {
		return currentPrimary, nil
	}

	return sql.NullInt64{}, nil
}

func nullablePrimaryRoleUpdate(primaryRoleID sql.NullInt64) any {
	if !primaryRoleID.Valid {
		return nil
	}
	return primaryRoleID.Int64
}

func normalizeRoleIDs(roleIDs []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(roleIDs))
	normalized := make([]uint64, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		if roleID == 0 {
			continue
		}
		if _, ok := seen[roleID]; ok {
			continue
		}
		seen[roleID] = struct{}{}
		normalized = append(normalized, roleID)
	}
	return normalized
}

func containsRoleID(roleIDs []uint64, roleID uint64) bool {
	for _, item := range roleIDs {
		if item == roleID {
			return true
		}
	}
	return false
}
