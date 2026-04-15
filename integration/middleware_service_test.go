//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	"paigram/internal/service/user"
)

// TestMiddlewareServiceIntegration tests MiddlewareService with real database
func TestMiddlewareServiceIntegration(t *testing.T) {
	stack := newIntegrationStack(t)
	serviceGroup := user.NewServiceGroup(stack.DB)

	t.Run("GetUserRoles", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Create test roles
		role1 := &model.Role{Name: "test-role-1", DisplayName: "Test Role 1"}
		role2 := &model.Role{Name: "test-role-2", DisplayName: "Test Role 2"}
		require.NoError(t, stack.DB.Create(role1).Error)
		require.NoError(t, stack.DB.Create(role2).Error)

		// Assign roles to user
		userRole1 := &model.UserRole{UserID: testUser.ID, RoleID: role1.ID, GrantedBy: testUser.ID}
		userRole2 := &model.UserRole{UserID: testUser.ID, RoleID: role2.ID, GrantedBy: testUser.ID}
		require.NoError(t, stack.DB.Create(userRole1).Error)
		require.NoError(t, stack.DB.Create(userRole2).Error)

		// Test GetUserRoles
		roleIDs, err := serviceGroup.MiddlewareService.GetUserRoles(testUser.ID)

		require.NoError(t, err)
		assert.Len(t, roleIDs, 2)
		assert.Contains(t, roleIDs, role1.ID)
		assert.Contains(t, roleIDs, role2.ID)

		// Test with user that has no roles
		testUser2 := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User 2",
			},
		}
		require.NoError(t, stack.DB.Create(testUser2).Error)

		roleIDs2, err := serviceGroup.MiddlewareService.GetUserRoles(testUser2.ID)
		require.NoError(t, err)
		assert.Empty(t, roleIDs2)
	})

	t.Run("HasAnyRole", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for HasAnyRole",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Create test roles
		adminRole := &model.Role{Name: "admin", DisplayName: "Admin"}
		moderatorRole := &model.Role{Name: "moderator", DisplayName: "Moderator"}
		userRole := &model.Role{Name: "user", DisplayName: "User"}
		require.NoError(t, stack.DB.Create(adminRole).Error)
		require.NoError(t, stack.DB.Create(moderatorRole).Error)
		require.NoError(t, stack.DB.Create(userRole).Error)

		// Assign only user role
		userRoleAssignment := &model.UserRole{UserID: testUser.ID, RoleID: userRole.ID, GrantedBy: testUser.ID}
		require.NoError(t, stack.DB.Create(userRoleAssignment).Error)

		// Test has role
		hasRole, err := serviceGroup.MiddlewareService.HasAnyRole(testUser.ID, []string{"user"})
		require.NoError(t, err)
		assert.True(t, hasRole)

		// Test doesn't have role
		hasRole, err = serviceGroup.MiddlewareService.HasAnyRole(testUser.ID, []string{"admin", "moderator"})
		require.NoError(t, err)
		assert.False(t, hasRole)

		// Test with empty role list
		hasRole, err = serviceGroup.MiddlewareService.HasAnyRole(testUser.ID, []string{})
		require.NoError(t, err)
		assert.False(t, hasRole)

		// Test with one matching role in list
		hasRole, err = serviceGroup.MiddlewareService.HasAnyRole(testUser.ID, []string{"admin", "user"})
		require.NoError(t, err)
		assert.True(t, hasRole)
	})

	t.Run("GetSessionByAccessToken", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for Session",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Create test session
		now := time.Now()
		testSession := &model.UserSession{
			UserID:           testUser.ID,
			AccessTokenHash:  "test-access-token-hash",
			RefreshTokenHash: "test-refresh-token-hash",
			AccessExpiry:     now.Add(1 * time.Hour),
			RefreshExpiry:    now.Add(24 * time.Hour),
			UserAgent:        "test-agent",
			ClientIP:         "127.0.0.1",
		}
		require.NoError(t, stack.DB.Create(testSession).Error)

		// Test session found
		session, err := serviceGroup.MiddlewareService.GetSessionByAccessToken("test-access-token-hash")
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, testSession.ID, session.ID)
		assert.Equal(t, testUser.ID, session.UserID)

		// Test session not found
		session, err = serviceGroup.MiddlewareService.GetSessionByAccessToken("nonexistent-token")
		require.NoError(t, err)
		assert.Nil(t, session)
	})

	t.Run("GetSessionByID", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for GetSessionByID",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Create test session
		now := time.Now()
		testSession := &model.UserSession{
			UserID:           testUser.ID,
			AccessTokenHash:  "test-session-by-id-hash",
			RefreshTokenHash: "test-refresh-by-id-hash",
			AccessExpiry:     now.Add(1 * time.Hour),
			RefreshExpiry:    now.Add(24 * time.Hour),
			UserAgent:        "test-agent",
			ClientIP:         "127.0.0.1",
		}
		require.NoError(t, stack.DB.Create(testSession).Error)

		// Test session found by ID
		session, err := serviceGroup.MiddlewareService.GetSessionByID(testSession.ID)
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, testSession.ID, session.ID)
		assert.Equal(t, testUser.ID, session.UserID)
		assert.Equal(t, "test-session-by-id-hash", session.AccessTokenHash)

		// Test session not found
		session, err = serviceGroup.MiddlewareService.GetSessionByID(999999)
		require.NoError(t, err)
		assert.Nil(t, session)
	})

	t.Run("GetUserByID", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for GetUserByID",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Test user found
		user, err := serviceGroup.MiddlewareService.GetUserByID(testUser.ID)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, testUser.ID, user.ID)
		assert.Equal(t, model.UserStatusActive, user.Status)

		// Test user not found
		user, err = serviceGroup.MiddlewareService.GetUserByID(999999)
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("GetTwoFactorSecret", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for 2FA",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Create 2FA record
		twoFactor := &model.UserTwoFactor{
			UserID:    testUser.ID,
			Secret:    "encrypted-totp-secret",
			EnabledAt: time.Now(),
		}
		require.NoError(t, stack.DB.Create(twoFactor).Error)

		// Test 2FA secret found
		secret, err := serviceGroup.MiddlewareService.GetTwoFactorSecret(testUser.ID)
		require.NoError(t, err)
		assert.Equal(t, "encrypted-totp-secret", secret)

		// Test 2FA not enabled for user
		testUser2 := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User without 2FA",
			},
		}
		require.NoError(t, stack.DB.Create(testUser2).Error)

		secret, err = serviceGroup.MiddlewareService.GetTwoFactorSecret(testUser2.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "2FA not enabled for user")
		assert.Empty(t, secret)
	})

	t.Run("UpdateUserLastLogin", func(t *testing.T) {
		// Create test user
		testUser := &model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
			Profile: model.UserProfile{
				DisplayName: "Test User for Last Login",
			},
		}
		require.NoError(t, stack.DB.Create(testUser).Error)

		// Update last login
		loginTime := time.Now()
		err := serviceGroup.MiddlewareService.UpdateUserLastLogin(testUser.ID, loginTime)
		require.NoError(t, err)

		// Verify update
		var updatedUser model.User
		require.NoError(t, stack.DB.First(&updatedUser, testUser.ID).Error)
		require.True(t, updatedUser.LastLoginAt.Valid)
		assert.WithinDuration(t, loginTime, updatedUser.LastLoginAt.Time, time.Second)

		// Test updating non-existent user
		err = serviceGroup.MiddlewareService.UpdateUserLastLogin(999999, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user 999999 not found")
	})
}
