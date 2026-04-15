//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	casbinlib "github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/casbin"
	"paigram/internal/model"
)

// TestAuthorityIntegration tests the complete authority management system
func TestAuthorityIntegration(t *testing.T) {
	stack := newIntegrationStack(t)

	// Reset and initialize Casbin enforcer for this test
	casbin.Reset()
	enforcer, err := casbin.InitEnforcer(stack.DB)
	require.NoError(t, err)
	require.NotNil(t, enforcer)

	// Seed initial data (pass enforcer to add Casbin policies)
	seedData := seedAuthorityTestData(t, stack, enforcer)

	// Run test suites
	t.Run("RoleManagement", func(t *testing.T) {
		testRoleManagement(t, stack, seedData)
	})

	t.Run("PermissionAssignment", func(t *testing.T) {
		testPermissionAssignment(t, stack, seedData)
	})

	t.Run("AuthorityUsers", func(t *testing.T) {
		testAuthorityUsers(t, stack, seedData)
	})

	t.Run("CasbinPolicyManagement", func(t *testing.T) {
		testCasbinPolicyManagement(t, stack, seedData)
	})

	t.Run("PermissionMiddleware", func(t *testing.T) {
		testPermissionMiddleware(t, stack, seedData, enforcer)
	})

	t.Run("EdgeCases", func(t *testing.T) {
		testEdgeCases(t, stack, seedData)
	})
}

// authorityTestData holds seed data for tests
type authorityTestData struct {
	adminUser      *model.User
	moderatorUser  *model.User
	regularUser    *model.User
	adminRole      *model.Role
	moderatorRole  *model.Role
	userRole       *model.Role
	permissions    []model.Permission
	adminToken     string
	moderatorToken string
	userToken      string
}

// seedAuthorityTestData creates test users, roles, and permissions
func seedAuthorityTestData(t *testing.T, stack *integrationStack, enforcer *casbinlib.SyncedCachedEnforcer) *authorityTestData {
	t.Helper()

	seed := &authorityTestData{}

	// Create permissions directly in database
	perms := []struct {
		name        string
		resource    string
		action      string
		description string
	}{
		{"user:read", "user", "read", "Read user information"},
		{"user:write", "user", "write", "Create or update users"},
		{"user:delete", "user", "delete", "Delete users"},
		{"role:read", "role", "read", "Read role information"},
		{"role:write", "role", "write", "Create or update roles"},
		{"role:delete", "role", "delete", "Delete roles"},
		{"permission:manage", "permission", "manage", "Manage all permissions"},
	}

	for _, p := range perms {
		perm := model.Permission{
			Name:        p.name,
			Resource:    p.resource,
			Action:      p.action,
			Description: p.description,
		}
		err := stack.DB.Create(&perm).Error
		require.NoError(t, err)
		seed.permissions = append(seed.permissions, perm)
	}

	// Create roles directly in database
	adminRole := model.Role{
		Name:        "admin",
		DisplayName: "Administrator",
		Description: "Full system access",
		IsSystem:    true,
	}
	err := stack.DB.Create(&adminRole).Error
	require.NoError(t, err)
	seed.adminRole = &adminRole

	moderatorRole := model.Role{
		Name:        "moderator",
		DisplayName: "Moderator",
		Description: "Moderate users",
		IsSystem:    true,
	}
	err = stack.DB.Create(&moderatorRole).Error
	require.NoError(t, err)
	seed.moderatorRole = &moderatorRole

	userRole := model.Role{
		Name:        "user",
		DisplayName: "Regular User",
		Description: "Standard user access",
		IsSystem:    true,
	}
	err = stack.DB.Create(&userRole).Error
	require.NoError(t, err)
	seed.userRole = &userRole

	// Assign permissions to roles via database
	// Admin role gets all permissions
	for _, p := range seed.permissions {
		rolePermission := model.RolePermission{
			RoleID:       adminRole.ID,
			PermissionID: p.ID,
		}
		err = stack.DB.Create(&rolePermission).Error
		require.NoError(t, err)
	}

	// Moderator role gets user-related permissions
	for _, p := range seed.permissions {
		if p.Resource == "user" {
			rolePermission := model.RolePermission{
				RoleID:       moderatorRole.ID,
				PermissionID: p.ID,
			}
			err = stack.DB.Create(&rolePermission).Error
			require.NoError(t, err)
		}
	}

	// User role gets read-only user permission
	for _, p := range seed.permissions {
		if p.Name == "user:read" {
			rolePermission := model.RolePermission{
				RoleID:       userRole.ID,
				PermissionID: p.ID,
			}
			err = stack.DB.Create(&rolePermission).Error
			require.NoError(t, err)
		}
	}

	// Add Casbin policies for admin role (full access to authority endpoints)
	adminRoleIDStr := fmt.Sprintf("%d", adminRole.ID)
	adminPolicies := [][]string{
		{adminRoleIDStr, "/api/v1/authorities", "GET"},
		{adminRoleIDStr, "/api/v1/authorities/:id", "GET"},
		{adminRoleIDStr, "/api/v1/authorities", "POST"},
		{adminRoleIDStr, "/api/v1/authorities/:id", "PUT"},
		{adminRoleIDStr, "/api/v1/authorities/:id", "PATCH"},
		{adminRoleIDStr, "/api/v1/authorities/:id", "DELETE"},
		{adminRoleIDStr, "/api/v1/authorities/:id/users", "GET"},
		{adminRoleIDStr, "/api/v1/authorities/:id/users", "PUT"},
		{adminRoleIDStr, "/api/v1/authorities/:id/permissions", "POST"},
		{adminRoleIDStr, "/api/v1/authorities/:id/permissions", "GET"},
		{adminRoleIDStr, "/api/v1/casbin/authorities/:id/policies", "PUT"},
		{adminRoleIDStr, "/api/v1/casbin/authorities/:id/policies", "GET"},
	}
	_, err = enforcer.AddPolicies(adminPolicies)
	require.NoError(t, err)

	// Add Casbin policies for moderator role (read-only)
	modRoleIDStr := fmt.Sprintf("%d", moderatorRole.ID)
	modPolicies := [][]string{
		{modRoleIDStr, "/api/v1/authorities", "GET"},
		{modRoleIDStr, "/api/v1/authorities/:id", "GET"},
		{modRoleIDStr, "/api/v1/authorities/:id/users", "GET"},
		{modRoleIDStr, "/api/v1/authorities/:id/permissions", "GET"},
		{modRoleIDStr, "/api/v1/casbin/authorities/:id/policies", "GET"},
	}
	_, err = enforcer.AddPolicies(modPolicies)
	require.NoError(t, err)

	// Reload policies to ensure they're active
	err = enforcer.LoadPolicy()
	require.NoError(t, err)

	// Verify policies are loaded for admin role
	hasPolicy, err := enforcer.Enforce(adminRoleIDStr, "/api/v1/authorities", "GET")
	require.NoError(t, err)
	require.True(t, hasPolicy, "Admin role should have GET access to /api/v1/authorities")

	hasPolicy, err = enforcer.Enforce(adminRoleIDStr, "/api/v1/casbin/authorities/1/policies", "GET")
	require.NoError(t, err)
	require.True(t, hasPolicy, "Admin role should have GET access to /api/v1/casbin/authorities/1/policies")

	// Create test users with real authentication
	adminUserID, adminToken, _, _, _ := registerAndLogin(t, stack, "admin-auth@example.com", "AdminPass123!")
	seed.adminUser = &model.User{ID: adminUserID}
	seed.adminToken = adminToken

	moderatorUserID, moderatorToken, _, _, _ := registerAndLogin(t, stack, "moderator-auth@example.com", "ModPass123!")
	seed.moderatorUser = &model.User{ID: moderatorUserID}
	seed.moderatorToken = moderatorToken

	regularUserID, userToken, _, _, _ := registerAndLogin(t, stack, "user-auth@example.com", "UserPass123!")
	seed.regularUser = &model.User{ID: regularUserID}
	seed.userToken = userToken

	// Assign roles to users directly via database
	// Admin role - check if already exists first
	var existingAdminRole model.UserRole
	err = stack.DB.Where("user_id = ? AND role_id = ?", seed.adminUser.ID, adminRole.ID).First(&existingAdminRole).Error
	if err != nil {
		// Only create if doesn't exist
		userRole1 := model.UserRole{
			UserID:    seed.adminUser.ID,
			RoleID:    adminRole.ID,
			GrantedBy: seed.adminUser.ID,
		}
		err = stack.DB.Create(&userRole1).Error
		require.NoError(t, err)
	}

	// Moderator role - check if already exists first
	var existingModRole model.UserRole
	err = stack.DB.Where("user_id = ? AND role_id = ?", seed.moderatorUser.ID, moderatorRole.ID).First(&existingModRole).Error
	if err != nil {
		// Only create if doesn't exist
		userRole2 := model.UserRole{
			UserID:    seed.moderatorUser.ID,
			RoleID:    moderatorRole.ID,
			GrantedBy: seed.adminUser.ID,
		}
		err = stack.DB.Create(&userRole2).Error
		require.NoError(t, err)
	}

	// User role - check if already exists first
	var existingUserRole model.UserRole
	err = stack.DB.Where("user_id = ? AND role_id = ?", seed.regularUser.ID, userRole.ID).First(&existingUserRole).Error
	if err != nil {
		// Only create if doesn't exist
		userRole3 := model.UserRole{
			UserID:    seed.regularUser.ID,
			RoleID:    userRole.ID,
			GrantedBy: seed.adminUser.ID,
		}
		err = stack.DB.Create(&userRole3).Error
		require.NoError(t, err)
	}

	return seed
}

// registerAndLogin registers a new user and returns their credentials
func registerAndLogin(t *testing.T, stack *integrationStack, email, password string) (uint64, string, string, string, string) {
	t.Helper()

	// Register
	registerRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        email,
		"password":     password,
		"display_name": "Test User",
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, registerRes.Code, registerRes.Body.String())
	registerData := decodeResponseData(t, registerRes)
	verificationToken := registerData["verification_token"].(string)

	// Verify email
	verifyRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{
		"email": email,
		"token": verificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, verifyRes.Code, verifyRes.Body.String())

	// Login
	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{"User-Agent": "AuthorityIntegrationTest/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
	loginData := decodeResponseData(t, loginRes)

	userID := uint64(loginData["user_id"].(float64))
	accessToken := loginData["access_token"].(string)
	refreshToken := loginData["refresh_token"].(string)

	return userID, accessToken, refreshToken, email, password
}

// testRoleManagement tests CRUD operations for roles
func testRoleManagement(t *testing.T, stack *integrationStack, seed *authorityTestData) {
	t.Run("CreateRole", func(t *testing.T) {
		resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/authorities", map[string]any{
			"name":           "test_role",
			"description":    "Test role for integration tests",
			"permission_ids": []uint{uint(seed.permissions[0].ID)},
		}, authHeaders(seed.adminToken))

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		assert.NotNil(t, result["data"])
	})

	t.Run("GetRoleByID", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			fmt.Sprintf("/api/v1/authorities/%d", seed.adminRole.ID), nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		data, ok := result["data"].(map[string]any)
		require.True(t, ok, "expected data map in response, got %T", result["data"])
		assert.Equal(t, "admin", data["name"])
		permissions, ok := data["permissions"].([]any)
		require.True(t, ok, "expected permissions array in response, got %T", data["permissions"])
		assert.NotEmpty(t, permissions)
	})

	t.Run("ListRoles", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			"/api/v1/authorities?page=1&page_size=10", nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)

		// Debug: print the response
		t.Logf("ListRoles response: %+v", result)

		require.NotNil(t, result["data"], "response data should not be nil")
		data, ok := result["data"].(map[string]any)
		require.True(t, ok, "expected data map in response, got %T", result["data"])
		assert.NotZero(t, data["total"])
		assert.NotEmpty(t, data["data"])
	})

	t.Run("UpdateRole", func(t *testing.T) {
		// Create a role to update
		var testRole model.Role
		testRole.Name = "update_test_role"
		testRole.DisplayName = "Update Test"
		testRole.Description = "Original description"
		require.NoError(t, stack.DB.Create(&testRole).Error)

		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d", testRole.ID), map[string]any{
				"name":        "update_test_role",
				"description": "Updated description",
			}, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		// Verify update
		var updated model.Role
		require.NoError(t, stack.DB.First(&updated, testRole.ID).Error)
		assert.Equal(t, "Updated description", updated.Description)
	})

	t.Run("UpdateRoleClearsDescription", func(t *testing.T) {
		var testRole model.Role
		testRole.Name = "clear_description_role"
		testRole.DisplayName = "Clear Description"
		testRole.Description = "Will be cleared"
		require.NoError(t, stack.DB.Create(&testRole).Error)

		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d", testRole.ID), map[string]any{
				"description": "",
			}, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var updated model.Role
		require.NoError(t, stack.DB.First(&updated, testRole.ID).Error)
		assert.Equal(t, "", updated.Description)
	})

	t.Run("UpdateRoleRejectsEmptyName", func(t *testing.T) {
		var testRole model.Role
		testRole.Name = "reject_empty_name_role"
		testRole.DisplayName = "Reject Empty Name"
		require.NoError(t, stack.DB.Create(&testRole).Error)

		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d", testRole.ID), map[string]any{
				"name": "",
			}, headers)

		assert.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	})

	t.Run("CreateRoleWithPermissionsUpdatesRuntimeAuthorizationImmediately", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		var roleReadPermission model.Permission
		require.NoError(t, stack.DB.Where("name = ?", "role:read").First(&roleReadPermission).Error)

		resp := performJSONRequest(t, stack.Router, http.MethodPost,
			"/api/v1/authorities", map[string]any{
				"name":           "create_perm_runtime_role",
				"description":    "created with permissions",
				"permission_ids": []uint{uint(roleReadPermission.ID)},
			}, headers)
		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		data, ok := result["data"].(map[string]any)
		require.True(t, ok, "expected role payload, got %T", result["data"])
		roleID := uint64(data["id"].(float64))

		enforcer := casbin.GetEnforcer()
		allowed, err := enforcer.Enforce(fmt.Sprint(roleID), "/api/v1/authorities", "GET")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("DeleteRole", func(t *testing.T) {
		// Create a role to delete
		var testRole model.Role
		testRole.Name = "delete_test_role"
		testRole.DisplayName = "Delete Test"
		testRole.IsSystem = false
		require.NoError(t, stack.DB.Create(&testRole).Error)

		enforcer := casbin.GetEnforcer()
		_, err := enforcer.AddPolicy(fmt.Sprint(testRole.ID), "/api/v1/custom/delete-role", "GET")
		require.NoError(t, err)
		require.NoError(t, enforcer.LoadPolicy())

		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodDelete,
			fmt.Sprintf("/api/v1/authorities/%d", testRole.ID), nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		hasPolicy, err := enforcer.Enforce(fmt.Sprint(testRole.ID), "/api/v1/custom/delete-role", "GET")
		require.NoError(t, err)
		assert.False(t, hasPolicy)

		// Verify deletion
		var deleted model.Role
		err = stack.DB.First(&deleted, testRole.ID).Error
		assert.Error(t, err)
	})
}

// testPermissionAssignment tests permission assignment operations
func testPermissionAssignment(t *testing.T, stack *integrationStack, seed *authorityTestData) {
	t.Run("AssignPermissionsToRole", func(t *testing.T) {
		// Create a new role
		var testRole model.Role
		testRole.Name = "perm_test_role"
		testRole.DisplayName = "Permission Test"
		require.NoError(t, stack.DB.Create(&testRole).Error)

		headers := authHeaders(seed.adminToken)

		permIDs := []uint{uint(seed.permissions[0].ID), uint(seed.permissions[1].ID)}

		resp := performJSONRequest(t, stack.Router, http.MethodPost,
			fmt.Sprintf("/api/v1/authorities/%d/permissions", testRole.ID), map[string]any{
				"permission_ids": permIDs,
			}, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})

	t.Run("AssignPermissionsUpdatesRuntimeAuthorizationImmediately", func(t *testing.T) {
		var testRole model.Role
		testRole.Name = "perm_runtime_role"
		testRole.DisplayName = "Permission Runtime"
		require.NoError(t, stack.DB.Create(&testRole).Error)

		var roleReadPermission model.Permission
		require.NoError(t, stack.DB.Where("name = ?", "role:read").First(&roleReadPermission).Error)

		adminHeaders := authHeaders(seed.adminToken)
		resp := performJSONRequest(t, stack.Router, http.MethodPost,
			fmt.Sprintf("/api/v1/authorities/%d/permissions", testRole.ID), map[string]any{
				"permission_ids": []uint{uint(roleReadPermission.ID)},
			}, adminHeaders)
		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		enforcer := casbin.GetEnforcer()
		allowed, err := enforcer.Enforce(fmt.Sprint(testRole.ID), "/api/v1/authorities", "GET")
		require.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("AssignPermissionsToMissingRoleReturnsNotFound", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)
		resp := performJSONRequest(t, stack.Router, http.MethodPost,
			"/api/v1/authorities/99999/permissions", map[string]any{
				"permission_ids": []uint{uint(seed.permissions[0].ID)},
			}, headers)
		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})

	t.Run("GetRolePermissions", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			fmt.Sprintf("/api/v1/authorities/%d/permissions", seed.adminRole.ID), nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		permissions, ok := result["data"].([]any)
		require.True(t, ok, "expected permissions array in response, got %T", result["data"])
		assert.NotEmpty(t, permissions)
	})

	t.Run("GetRolePermissionsForMissingRoleReturnsNotFound", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			"/api/v1/authorities/99999/permissions", nil, headers)

		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})
}

// testAuthorityUsers tests authority-owned user membership endpoints.
func testAuthorityUsers(t *testing.T, stack *integrationStack, seed *authorityTestData) {
	t.Run("GetAuthorityUsers", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.userRole.ID), nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		users, ok := result["data"].([]any)
		require.True(t, ok, "expected users array in response, got %T", result["data"])

		userIDs := make(map[uint64]struct{}, len(users))
		for _, rawUser := range users {
			user, ok := rawUser.(map[string]any)
			require.True(t, ok, "expected user object in response, got %T", rawUser)
			userIDs[uint64(user["id"].(float64))] = struct{}{}
		}

		assert.Contains(t, userIDs, seed.adminUser.ID)
		assert.Contains(t, userIDs, seed.moderatorUser.ID)
		assert.Contains(t, userIDs, seed.regularUser.ID)
	})

	t.Run("ReplaceAuthorityUsers", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)
		replacementUserIDs := []uint64{seed.adminUser.ID, seed.moderatorUser.ID}

		var originalAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.userRole.ID).Order("user_id ASC").Find(&originalAssignments).Error)
		require.Len(t, originalAssignments, 3)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.userRole.ID), map[string]any{
				"user_ids": replacementUserIDs,
			}, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var userRoles []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.userRole.ID).Order("user_id ASC").Find(&userRoles).Error)
		require.Len(t, userRoles, 2)
		assert.Equal(t, originalAssignments[0].ID, userRoles[0].ID)
		assert.Equal(t, seed.adminUser.ID, userRoles[0].UserID)
		assert.Equal(t, originalAssignments[0].GrantedBy, userRoles[0].GrantedBy)
		assert.True(t, originalAssignments[0].CreatedAt.Equal(userRoles[0].CreatedAt), "admin assignment timestamp should be preserved")
		assert.Equal(t, originalAssignments[1].ID, userRoles[1].ID)
		assert.Equal(t, seed.moderatorUser.ID, userRoles[1].UserID)
		assert.Equal(t, originalAssignments[1].GrantedBy, userRoles[1].GrantedBy)
		assert.True(t, originalAssignments[1].CreatedAt.Equal(userRoles[1].CreatedAt), "moderator assignment timestamp should be preserved")

		verifyResp := performJSONRequest(t, stack.Router, http.MethodGet,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.userRole.ID), nil, headers)
		require.Equal(t, http.StatusOK, verifyResp.Code, verifyResp.Body.String())

		var verifyResult map[string]any
		decodeJSON(t, verifyResp, &verifyResult)
		users, ok := verifyResult["data"].([]any)
		require.True(t, ok, "expected users array in response, got %T", verifyResult["data"])
		require.Len(t, users, 2)
	})

	t.Run("ReplaceAuthorityUsersProtectsCriticalRole", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		var originalAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&originalAssignments).Error)
		require.NotEmpty(t, originalAssignments)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.adminRole.ID), map[string]any{
				"user_ids": []uint64{},
			}, headers)

		assert.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())

		var afterAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&afterAssignments).Error)
		assert.Equal(t, originalAssignments, afterAssignments)
	})

	t.Run("ReplaceAuthorityUsersProtectsCriticalRoleWhenOnlyInactiveAdminsWouldRemain", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		inactiveAdminID, _, _, _, _ := registerAndLogin(t, stack, "inactive-admin-auth@example.com", "InactiveAdminPass123!")
		require.NoError(t, stack.DB.Model(&model.User{}).Where("id = ?", inactiveAdminID).Update("status", model.UserStatusSuspended).Error)
		require.NoError(t, stack.DB.Create(&model.UserRole{UserID: inactiveAdminID, RoleID: seed.adminRole.ID, GrantedBy: seed.adminUser.ID}).Error)

		var originalAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&originalAssignments).Error)
		require.Len(t, originalAssignments, 2)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.adminRole.ID), map[string]any{
				"user_ids": []uint64{inactiveAdminID},
			}, headers)

		assert.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())

		var afterAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&afterAssignments).Error)
		assert.Equal(t, originalAssignments, afterAssignments)
	})

	t.Run("ReplaceAuthorityUsersRequiresActiveAdminActorForCriticalRole", func(t *testing.T) {
		userRoleIDStr := fmt.Sprintf("%d", seed.userRole.ID)
		_, err := casbin.GetEnforcer().AddPolicy(userRoleIDStr, "/api/v1/authorities/:id/users", "PUT")
		require.NoError(t, err)
		require.NoError(t, casbin.GetEnforcer().LoadPolicy())

		headers := authHeaders(seed.userToken)

		var originalAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&originalAssignments).Error)
		require.NotEmpty(t, originalAssignments)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/authorities/%d/users", seed.adminRole.ID), map[string]any{
				"user_ids": []uint64{seed.adminUser.ID, seed.regularUser.ID},
			}, headers)

		assert.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())

		var afterAssignments []model.UserRole
		require.NoError(t, stack.DB.Where("role_id = ?", seed.adminRole.ID).Order("user_id ASC").Find(&afterAssignments).Error)
		assert.Equal(t, originalAssignments, afterAssignments)
	})

	t.Run("LegacyUserRoleWriteRoutesUnavailable", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		postResp := performJSONRequest(t, stack.Router, http.MethodPost,
			fmt.Sprintf("/api/v1/users/%d/roles", seed.regularUser.ID), map[string]any{
				"role_id": seed.adminRole.ID,
			}, headers)
		assert.Equal(t, http.StatusNotFound, postResp.Code, postResp.Body.String())

		deleteResp := performJSONRequest(t, stack.Router, http.MethodDelete,
			fmt.Sprintf("/api/v1/users/%d/roles/%d", seed.regularUser.ID, seed.userRole.ID), nil, headers)
		assert.Equal(t, http.StatusNotFound, deleteResp.Code, deleteResp.Body.String())
	})
}

// testCasbinPolicyManagement tests Casbin policy CRUD operations
func testCasbinPolicyManagement(t *testing.T, stack *integrationStack, seed *authorityTestData) {
	t.Run("UpdateCasbinPolicies", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		// Include all necessary policies for authority endpoints to allow subsequent GET request
		policies := []map[string]any{
			// User management policies
			{"path": "/api/v1/users", "method": "GET"},
			{"path": "/api/v1/users/:id", "method": "GET"},
			{"path": "/api/v1/users", "method": "POST"},
			// Session management policies
			{"path": "/api/v1/users/:id/sessions/:sessionId", "method": "DELETE"},
			// Authority endpoints policies (needed for subsequent tests)
			{"path": "/api/v1/authorities", "method": "GET"},
			{"path": "/api/v1/authorities/:id", "method": "GET"},
			{"path": "/api/v1/authorities", "method": "POST"},
			{"path": "/api/v1/authorities/:id", "method": "PUT"},
			{"path": "/api/v1/authorities/:id", "method": "DELETE"},
			{"path": "/api/v1/authorities/:id/users", "method": "GET"},
			{"path": "/api/v1/authorities/:id/users", "method": "PUT"},
			{"path": "/api/v1/authorities/:id/permissions", "method": "POST"},
			{"path": "/api/v1/authorities/:id/permissions", "method": "GET"},
			{"path": "/api/v1/casbin/authorities/:id/policies", "method": "PUT"},
			{"path": "/api/v1/casbin/authorities/:id/policies", "method": "GET"},
		}

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/casbin/authorities/%d/policies", seed.adminRole.ID), map[string]any{
				"policies": policies,
			}, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})

	t.Run("GetRolePolicies", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			fmt.Sprintf("/api/v1/casbin/authorities/%d/policies", seed.adminRole.ID), nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		var result map[string]any
		decodeJSON(t, resp, &result)
		data, ok := result["data"].(map[string]any)
		require.True(t, ok, "expected data map in response, got %T", result["data"])
		policies, ok := data["policies"].([]any)
		require.True(t, ok, "expected policies array, got %T", data["policies"])
		assert.NotEmpty(t, policies)
	})

	t.Run("VerifyPolicyEnforcement", func(t *testing.T) {
		// Add a specific policy
		headers := authHeaders(seed.adminToken)

		policies := []map[string]any{
			{"path": "/api/v1/test/resource", "method": "GET"},
		}

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/casbin/authorities/%d/policies", seed.moderatorRole.ID), map[string]any{
				"policies": policies,
			}, headers)

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

		// Verify enforcement
		enforcer := casbin.GetEnforcer()
		require.NotNil(t, enforcer)

		allowed, err := enforcer.Enforce(fmt.Sprint(seed.moderatorRole.ID), "/api/v1/test/resource", "GET")
		require.NoError(t, err)
		assert.True(t, allowed, "Policy should allow access")

		notAllowed, err := enforcer.Enforce(fmt.Sprint(seed.moderatorRole.ID), "/api/v1/test/resource", "DELETE")
		require.NoError(t, err)
		assert.False(t, notAllowed, "Policy should deny access")
	})

	t.Run("GetPoliciesForMissingAuthorityReturnsNotFound", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet,
			"/api/v1/casbin/authorities/99999/policies", nil, headers)

		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})

	t.Run("ReplacePoliciesForMissingAuthorityReturnsNotFound", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			"/api/v1/casbin/authorities/99999/policies", map[string]any{
				"policies": []map[string]any{{
					"path":   "/api/v1/users",
					"method": "GET",
				}},
			}, headers)

		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})
}

// testPermissionMiddleware tests the CasbinMiddleware enforcement
func testPermissionMiddleware(t *testing.T, stack *integrationStack, seed *authorityTestData, enforcer *casbinlib.SyncedCachedEnforcer) {
	t.Run("AdminAccessAllowed", func(t *testing.T) {
		// Add policy for admin to access authorities endpoint
		_, err := enforcer.AddPolicy(fmt.Sprint(seed.adminRole.ID), "/api/v1/authorities", "GET")
		require.NoError(t, err)

		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/authorities", nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})

	t.Run("ModeratorAccessRestricted", func(t *testing.T) {
		// Moderator should not have access without specific policy
		headers := authHeaders(seed.moderatorToken)

		resp := performJSONRequest(t, stack.Router, http.MethodDelete,
			"/api/v1/authorities/999", nil, headers)

		// Should be forbidden
		assert.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())
	})

	t.Run("UnauthorizedWithoutUserID", func(t *testing.T) {
		resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/authorities", nil, nil)

		assert.Equal(t, http.StatusUnauthorized, resp.Code, resp.Body.String())
	})

	t.Run("UserWithSpecificPermission", func(t *testing.T) {
		var existingAssignment model.UserRole
		err := stack.DB.Where("user_id = ? AND role_id = ?", seed.regularUser.ID, seed.userRole.ID).First(&existingAssignment).Error
		if err != nil {
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
			require.NoError(t, stack.DB.Create(&model.UserRole{
				UserID:    seed.regularUser.ID,
				RoleID:    seed.userRole.ID,
				GrantedBy: seed.adminUser.ID,
			}).Error)
		}

		// Add specific policy for regular user
		_, err = enforcer.AddPolicy(fmt.Sprint(seed.userRole.ID), "/api/v1/authorities", "GET")
		require.NoError(t, err)

		headers := authHeaders(seed.userToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/authorities", nil, headers)

		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})
}

// testEdgeCases tests error handling and edge cases
func testEdgeCases(t *testing.T, stack *integrationStack, seed *authorityTestData) {
	t.Run("GetNonExistentRole", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodGet, "/api/v1/authorities/99999", nil, headers)

		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})

	t.Run("CreateRoleWithInvalidData", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/authorities", map[string]any{
			"name": "a", // Too short
		}, headers)

		assert.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	})

	t.Run("DeleteSystemRole", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodDelete,
			fmt.Sprintf("/api/v1/authorities/%d", seed.adminRole.ID), nil, headers)

		// System roles should not be deletable
		assert.Contains(t, []int{http.StatusForbidden, http.StatusInternalServerError}, resp.Code)
	})

	t.Run("DuplicateRoleName", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/authorities", map[string]any{
			"name":        "admin", // Already exists
			"description": "Duplicate role",
		}, headers)

		// Should return 409 Conflict for duplicate name
		assert.Equal(t, http.StatusConflict, resp.Code)
	})

	t.Run("AssignNonExistentPermission", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPost,
			fmt.Sprintf("/api/v1/authorities/%d/permissions", seed.adminRole.ID), map[string]any{
				"permission_ids": []uint{99999}, // Non-existent
			}, headers)

		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError}, resp.Code)
	})

	t.Run("InvalidCasbinPolicy", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		policies := []map[string]any{
			{"path": "", "method": "INVALID"}, // Invalid method
		}

		resp := performJSONRequest(t, stack.Router, http.MethodPut,
			fmt.Sprintf("/api/v1/casbin/authorities/%d/policies", seed.adminRole.ID), map[string]any{
				"policies": policies,
			}, headers)

		assert.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	})

	t.Run("UpdateRoleWithInvalidID", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		resp := performJSONRequest(t, stack.Router, http.MethodPut, "/api/v1/authorities/invalid", map[string]any{
			"name": "new_name",
		}, headers)

		assert.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	})

	t.Run("RemoveNonExistentUserRoleAssociation", func(t *testing.T) {
		headers := authHeaders(seed.adminToken)

		// Use non-existent user ID and role ID combination
		nonExistentUserID := uint64(99999)
		nonExistentRoleID := uint64(99998)

		resp := performJSONRequest(t, stack.Router, http.MethodDelete,
			fmt.Sprintf("/api/v1/users/%d/roles/%d", nonExistentUserID, nonExistentRoleID), nil, headers)

		// Should return 404, not 204
		assert.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())
	})
}

// Helper function to decode JSON response
func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), v))
}
