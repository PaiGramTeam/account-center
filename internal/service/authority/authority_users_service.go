package authority

import (
	"time"

	"gorm.io/gorm"

	"paigram/internal/model"
	pkgerrors "paigram/pkg/errors"
)

// AuthorityUserInfo 角色下的用户信息。
type AuthorityUserInfo struct {
	ID           uint64    `json:"id"`
	DisplayName  string    `json:"display_name"`
	PrimaryEmail string    `json:"primary_email"`
	AssignedAt   time.Time `json:"assigned_at"`
	GrantedBy    uint64    `json:"granted_by"`
}

// GetAuthorityUsers 获取角色下的用户列表。
func (s *AuthorityService) GetAuthorityUsers(roleID uint) ([]AuthorityUserInfo, error) {
	if err := s.ensureAuthorityExists(s.db, roleID); err != nil {
		return nil, err
	}

	var users []AuthorityUserInfo
	err := s.db.Table("user_roles").
		Select("users.id, user_profiles.display_name, user_emails.email AS primary_email, user_roles.created_at AS assigned_at, user_roles.granted_by").
		Joins("JOIN users ON users.id = user_roles.user_id AND users.deleted_at IS NULL").
		Joins("LEFT JOIN user_profiles ON user_profiles.user_id = users.id").
		Joins("LEFT JOIN user_emails ON user_emails.user_id = users.id AND user_emails.is_primary = ?", true).
		Where("user_roles.role_id = ?", uint64(roleID)).
		Order("user_roles.created_at ASC").
		Scan(&users).Error
	if err != nil {
		return nil, err
	}

	return users, nil
}

// ReplaceAuthorityUsers 全量替换角色下的用户列表。
func (s *AuthorityService) ReplaceAuthorityUsers(roleID uint, userIDs []uint64, grantedBy uint64) error {
	normalizedUserIDs := normalizeAuthorityUserIDs(userIDs)

	return s.db.Transaction(func(tx *gorm.DB) error {
		role, err := s.getAuthority(tx, roleID)
		if err != nil {
			return err
		}

		if isCriticalAuthority(role) && len(normalizedUserIDs) == 0 {
			return pkgerrors.ErrSystemRoleProtect
		}

		if isCriticalAuthority(role) {
			var actingAdminCount int64
			if err := tx.Table("user_roles").
				Joins("JOIN users ON users.id = user_roles.user_id").
				Where("user_roles.role_id = ? AND user_roles.user_id = ? AND users.status = ?", uint64(roleID), grantedBy, model.UserStatusActive).
				Count(&actingAdminCount).Error; err != nil {
				return err
			}
			if actingAdminCount == 0 {
				return pkgerrors.ErrSystemRoleProtect
			}
		}

		if len(normalizedUserIDs) > 0 {
			var count int64
			if err := tx.Model(&model.User{}).Where("id IN ?", normalizedUserIDs).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(normalizedUserIDs)) {
				return gorm.ErrRecordNotFound
			}

			if isCriticalAuthority(role) {
				var activeCount int64
				if err := tx.Model(&model.User{}).Where("id IN ? AND status = ?", normalizedUserIDs, model.UserStatusActive).Count(&activeCount).Error; err != nil {
					return err
				}
				if activeCount == 0 {
					return pkgerrors.ErrSystemRoleProtect
				}
			}
		} else if isCriticalAuthority(role) {
			return pkgerrors.ErrSystemRoleProtect
		}

		var existingAssignments []model.UserRole
		if err := tx.Where("role_id = ?", uint64(roleID)).Find(&existingAssignments).Error; err != nil {
			return err
		}

		existingByUserID := make(map[uint64]model.UserRole, len(existingAssignments))
		for _, assignment := range existingAssignments {
			existingByUserID[assignment.UserID] = assignment
		}

		desiredUserIDs := make(map[uint64]struct{}, len(normalizedUserIDs))
		for _, userID := range normalizedUserIDs {
			desiredUserIDs[userID] = struct{}{}
		}

		removedUserIDs := make([]uint64, 0)
		for _, assignment := range existingAssignments {
			if _, keep := desiredUserIDs[assignment.UserID]; keep {
				continue
			}
			removedUserIDs = append(removedUserIDs, assignment.UserID)
		}
		if len(removedUserIDs) > 0 {
			if err := tx.Where("role_id = ? AND user_id IN ?", uint64(roleID), removedUserIDs).Delete(&model.UserRole{}).Error; err != nil {
				return err
			}
		}

		for _, userID := range normalizedUserIDs {
			if _, exists := existingByUserID[userID]; exists {
				continue
			}
			userRole := model.UserRole{
				UserID:    userID,
				RoleID:    uint64(roleID),
				GrantedBy: grantedBy,
			}
			if err := tx.Create(&userRole).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *AuthorityService) ensureAuthorityExists(db *gorm.DB, roleID uint) error {
	_, err := s.getAuthority(db, roleID)
	return err
}

func (s *AuthorityService) getAuthority(db *gorm.DB, roleID uint) (*model.Role, error) {
	var role model.Role
	if err := db.First(&role, uint64(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, pkgerrors.ErrRoleNotFound
		}
		return nil, err
	}

	return &role, nil
}

func normalizeAuthorityUserIDs(userIDs []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(userIDs))
	normalized := make([]uint64, 0, len(userIDs))
	for _, userID := range userIDs {
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		normalized = append(normalized, userID)
	}

	return normalized
}

func isCriticalAuthority(role *model.Role) bool {
	return role != nil && role.IsSystem && role.Name == model.RoleAdmin
}
