package casbin

import (
	"fmt"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"

	internalcasbin "paigram/internal/casbin"
	"paigram/internal/model"
)

// MigratePermissionsToCasbin syncs role permissions into explicit Casbin policies.
func (s *CasbinService) MigratePermissionsToCasbin() error {
	enforcer := internalcasbin.GetEnforcer()
	if enforcer == nil {
		return fmt.Errorf("casbin enforcer not initialized")
	}

	type roleRecord struct {
		ID uint64
	}

	var roles []roleRecord
	if err := s.db.Model(&model.Role{}).Select("id").Find(&roles).Error; err != nil {
		return err
	}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		for _, role := range roles {
			policies, err := loadRolePolicies(tx, role.ID)
			if err != nil {
				return err
			}

			existingRules, err := loadAuthorityPolicyRules(tx, fmt.Sprint(role.ID))
			if err != nil {
				return err
			}
			policies = mergeCustomAndManagedPolicies(existingRules, policies)

			if err := replaceAuthorityPolicyRules(tx, fmt.Sprint(role.ID), policies); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return fmt.Errorf("migrate permissions to casbin: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return fmt.Errorf("reload migrated casbin policies: %w", err)
	}

	return nil
}

func loadRolePolicies(tx *gorm.DB, roleID uint64) ([]CasbinPolicyInfo, error) {
	var permissionNames []string
	if err := tx.Table("permissions").
		Select("permissions.name").
		Joins("INNER JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", roleID).
		Scan(&permissionNames).Error; err != nil {
		return nil, err
	}

	policies := make([]CasbinPolicyInfo, 0)
	for _, permissionName := range permissionNames {
		policies = append(policies, policiesForPermissionName(permissionName)...)
	}

	return policies, nil
}

func policiesForPermissionName(permissionName string) []CasbinPolicyInfo {
	rules := internalcasbin.PoliciesForPermission(permissionName)
	if len(rules) == 0 {
		switch permissionName {
		case model.PermUserWrite:
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceUser, model.ActionCreate))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceUser, model.ActionUpdate))...)
		case model.PermRoleWrite:
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceRole, model.ActionCreate))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceRole, model.ActionUpdate))...)
		case model.PermPermissionWrite:
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourcePermission, model.ActionCreate))...)
		case model.PermBotWrite:
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceBot, model.ActionCreate))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceBot, model.ActionUpdate))...)
		case model.PermUserManage:
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceSession, model.ActionRead))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceSession, model.ActionDelete))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceSession, model.ActionList))...)
			rules = append(rules, internalcasbin.PoliciesForPermission(model.BuildPermissionName(model.ResourceUser, model.ActionRead))...)
		}
	}

	policies := make([]CasbinPolicyInfo, 0, len(rules))
	for _, rule := range rules {
		policies = append(policies, CasbinPolicyInfo{Path: rule.Path, Method: rule.Method})
	}

	return policies
}

func loadAuthorityPolicyRules(tx *gorm.DB, roleID string) ([]gormadapter.CasbinRule, error) {
	var rules []gormadapter.CasbinRule
	if err := tx.Where("ptype = ? AND v0 = ?", "p", roleID).Order("id ASC").Find(&rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func replaceAuthorityPolicyRules(tx *gorm.DB, roleID string, policies []CasbinPolicyInfo) error {
	uniquePolicies := uniquePolicyRules(roleID, policies)
	if err := tx.Where("ptype = ? AND v0 = ?", "p", roleID).Delete(&gormadapter.CasbinRule{}).Error; err != nil {
		return err
	}

	for _, policy := range uniquePolicies {
		if err := tx.Create(&gormadapter.CasbinRule{
			Ptype: "p",
			V0:    policy[0],
			V1:    policy[1],
			V2:    policy[2],
		}).Error; err != nil {
			return err
		}
	}

	return nil
}

func restoreAuthorityPolicyRules(tx *gorm.DB, roleID string, rules []gormadapter.CasbinRule) error {
	if err := tx.Where("ptype = ? AND v0 = ?", "p", roleID).Delete(&gormadapter.CasbinRule{}).Error; err != nil {
		return err
	}

	for _, rule := range rules {
		restored := gormadapter.CasbinRule{
			Ptype: rule.Ptype,
			V0:    rule.V0,
			V1:    rule.V1,
			V2:    rule.V2,
			V3:    rule.V3,
			V4:    rule.V4,
			V5:    rule.V5,
		}
		if err := tx.Create(&restored).Error; err != nil {
			return err
		}
	}

	return nil
}

func casbinRulesToPolicyInfo(rules []gormadapter.CasbinRule) []CasbinPolicyInfo {
	policies := make([]CasbinPolicyInfo, 0, len(rules))
	for _, rule := range rules {
		if rule.Ptype != "p" || rule.V1 == "" || rule.V2 == "" {
			continue
		}
		policies = append(policies, CasbinPolicyInfo{
			Path:   rule.V1,
			Method: rule.V2,
		})
	}
	return policies
}

func mergeCustomAndManagedPolicies(existingRules []gormadapter.CasbinRule, managedPolicies []CasbinPolicyInfo) []CasbinPolicyInfo {
	managedRuleSet := make(map[string]struct{})
	for _, rule := range internalcasbin.AllManagedPolicies() {
		managedRuleSet[rule.Path+"\x00"+rule.Method] = struct{}{}
	}

	merged := make([]CasbinPolicyInfo, 0, len(existingRules)+len(managedPolicies))
	for _, rule := range existingRules {
		if rule.Ptype != "p" || rule.V1 == "" || rule.V2 == "" {
			continue
		}
		if _, ok := managedRuleSet[rule.V1+"\x00"+rule.V2]; ok {
			continue
		}
		merged = append(merged, CasbinPolicyInfo{Path: rule.V1, Method: rule.V2})
	}

	merged = append(merged, managedPolicies...)
	return merged
}
