package casbin

import (
	"fmt"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
	internalcasbin "paigram/internal/casbin"
	"paigram/internal/model"
	"paigram/pkg/errors"
)

type CasbinPolicyInfo struct {
	Path   string
	Method string
}

type CasbinService struct {
	db *gorm.DB
}

// ReplaceAuthorityPolicies replaces all API policies for an authority.
func (s *CasbinService) ReplaceAuthorityPolicies(roleID uint, policies []CasbinPolicyInfo) error {
	enforcer := internalcasbin.GetEnforcer()
	if enforcer == nil {
		return errors.ErrCasbinEnforce
	}
	if err := s.ensureAuthorityExists(roleID); err != nil {
		return err
	}

	roleIDStr := fmt.Sprint(roleID)
	previousRules, err := loadAuthorityPolicyRules(s.db, roleIDStr)
	if err != nil {
		return fmt.Errorf("load existing authority policies: %w", err)
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return replaceAuthorityPolicyRules(tx, roleIDStr, policies)
	}); err != nil {
		return fmt.Errorf("replace authority policies: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		restoreErr := s.db.Transaction(func(tx *gorm.DB) error {
			return restoreAuthorityPolicyRules(tx, roleIDStr, previousRules)
		})
		if restoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; restore authority policies: %v", err, restoreErr)
		}

		if reloadRestoreErr := enforcer.LoadPolicy(); reloadRestoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; reload restored authority policies: %v", err, reloadRestoreErr)
		}

		return fmt.Errorf("reload authority policies: %w", err)
	}

	return nil
}

// SyncAuthorityPermissionPolicies refreshes one authority's managed Casbin rules from role permissions while preserving custom policies.
func (s *CasbinService) SyncAuthorityPermissionPolicies(roleID uint) error {
	enforcer := internalcasbin.GetEnforcer()
	if enforcer == nil {
		return errors.ErrCasbinEnforce
	}
	if err := s.ensureAuthorityExists(roleID); err != nil {
		return err
	}

	roleIDStr := fmt.Sprint(roleID)
	previousRules, err := loadAuthorityPolicyRules(s.db, roleIDStr)
	if err != nil {
		return fmt.Errorf("load existing authority policies: %w", err)
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		managedPolicies, err := loadRolePolicies(tx, uint64(roleID))
		if err != nil {
			return err
		}

		existingRules, err := loadAuthorityPolicyRules(tx, roleIDStr)
		if err != nil {
			return err
		}

		return replaceAuthorityPolicyRules(tx, roleIDStr, mergeCustomAndManagedPolicies(existingRules, managedPolicies))
	}); err != nil {
		return fmt.Errorf("sync authority policies: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		restoreErr := s.db.Transaction(func(tx *gorm.DB) error {
			return restoreAuthorityPolicyRules(tx, roleIDStr, previousRules)
		})
		if restoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; restore authority policies: %v", err, restoreErr)
		}
		if reloadRestoreErr := enforcer.LoadPolicy(); reloadRestoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; reload restored authority policies: %v", err, reloadRestoreErr)
		}
		return fmt.Errorf("reload authority policies: %w", err)
	}

	return nil
}

// GetAuthorityPolicies returns all API policies for an authority.
func (s *CasbinService) GetAuthorityPolicies(roleID uint) ([]CasbinPolicyInfo, error) {
	enforcer := internalcasbin.GetEnforcer()
	if enforcer == nil {
		return nil, errors.ErrCasbinEnforce
	}
	if err := s.ensureAuthorityExists(roleID); err != nil {
		return nil, err
	}

	roleIDStr := fmt.Sprint(roleID)
	policies := enforcer.GetFilteredPolicy(0, roleIDStr)

	result := make([]CasbinPolicyInfo, 0, len(policies))
	for _, policy := range policies {
		if len(policy) < 3 {
			continue
		}

		result = append(result, CasbinPolicyInfo{
			Path:   policy[1],
			Method: policy[2],
		})
	}

	return result, nil
}

// DeleteAuthorityPolicies removes all API policies for an authority.
func (s *CasbinService) DeleteAuthorityPolicies(roleID uint) error {
	enforcer := internalcasbin.GetEnforcer()
	if enforcer == nil {
		return errors.ErrCasbinEnforce
	}

	roleIDStr := fmt.Sprint(roleID)
	previousRules, err := loadAuthorityPolicyRules(s.db, roleIDStr)
	if err != nil {
		return fmt.Errorf("load existing authority policies: %w", err)
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return tx.Where("ptype = ? AND v0 = ?", "p", roleIDStr).Delete(&gormadapter.CasbinRule{}).Error
	}); err != nil {
		return fmt.Errorf("delete authority policies: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		restoreErr := s.db.Transaction(func(tx *gorm.DB) error {
			return restoreAuthorityPolicyRules(tx, roleIDStr, previousRules)
		})
		if restoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; restore authority policies: %v", err, restoreErr)
		}
		if reloadRestoreErr := enforcer.LoadPolicy(); reloadRestoreErr != nil {
			return fmt.Errorf("reload authority policies: %w; reload restored authority policies: %v", err, reloadRestoreErr)
		}
		return fmt.Errorf("reload authority policies: %w", err)
	}

	return nil
}

func uniquePolicyRules(roleID string, policies []CasbinPolicyInfo) [][]string {
	policyMap := make(map[string]struct{}, len(policies))
	uniquePolicies := make([][]string, 0, len(policies))

	for _, policy := range policies {
		key := roleID + "\x00" + policy.Path + "\x00" + policy.Method
		if _, exists := policyMap[key]; exists {
			continue
		}

		policyMap[key] = struct{}{}
		uniquePolicies = append(uniquePolicies, []string{roleID, policy.Path, policy.Method})
	}

	return uniquePolicies
}

func (s *CasbinService) ensureAuthorityExists(roleID uint) error {
	var role model.Role
	if err := s.db.Select("id").First(&role, uint64(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.ErrRoleNotFound
		}
		return err
	}

	return nil
}
