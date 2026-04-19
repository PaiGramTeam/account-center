package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/response"
	serviceUser "paigram/internal/service/user"
	"paigram/internal/testutil"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db := testutil.OpenMySQLTestDB(t, "user",
		&model.User{},
		&model.UserProfile{},
		&model.UserCredential{},
		&model.UserEmail{},
		&model.UserSession{},
		&model.UserTwoFactor{},
		&model.Role{},
		&model.Permission{},
		&model.UserRole{},
		&model.RolePermission{},
	)

	return db
}

func setupTestHandler(db *gorm.DB) *Handler {
	serviceGroup := serviceUser.NewServiceGroup(db)
	return NewHandlerWithDB(&serviceGroup.UserService, db)
}

func TestManagementSwaggerAnnotationsUseAdminUserNamespace(t *testing.T) {
	userHandlerSource, err := os.ReadFile("user_handler.go")
	require.NoError(t, err)
	userSource := string(userHandlerSource)
	assert.NotContains(t, userSource, "@Router /api/v1/users ")
	assert.NotContains(t, userSource, "@Router /api/v1/users/")
	assert.NotContains(t, userSource, "swagger:route PATCH /api/v1/users/")
	assert.NotContains(t, userSource, "swagger:route POST /api/v1/users/")
	assert.NotContains(t, userSource, "swagger:route GET /api/v1/users/")

	loginLogSourceBytes, err := os.ReadFile(filepath.Join("login_logs.go"))
	require.NoError(t, err)
	loginLogSource := string(loginLogSourceBytes)
	assert.NotContains(t, loginLogSource, "@Router /api/v1/users/")
}

func TestHandler_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	// Create a test role for role assignment tests
	role := model.Role{Name: "user", DisplayName: "User", Description: "default user role"}
	require.NoError(t, db.Create(&role).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
		wantErr    bool
	}{
		{
			name: "valid user creation",
			body: map[string]interface{}{
				"email":              "testuser@example.com",
				"password":           "TestPass123!",
				"display_name":       "Test User",
				"primary_login_type": "email",
				"avatar_url":         "https://example.com/avatar.jpg",
				"bio":                "Test bio",
				"locale":             "en_US",
			},
			wantStatus: http.StatusCreated,
			wantErr:    false,
		},
		{
			name: "valid user with custom locale",
			body: map[string]interface{}{
				"email":              "testuser2@example.com",
				"password":           "TestPass123!",
				"display_name":       "Test User 2",
				"primary_login_type": "email",
				"locale":             "zh_CN",
			},
			wantStatus: http.StatusCreated,
			wantErr:    false,
		},
		{
			name: "reject roles on create",
			body: map[string]interface{}{
				"email":              "testuser3@example.com",
				"password":           "TestPass123!",
				"display_name":       "Test User 3",
				"primary_login_type": "email",
				"roles":              []string{"user"},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "missing email",
			body: map[string]interface{}{
				"password":           "TestPass123!",
				"display_name":       "Test User",
				"primary_login_type": "email",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "missing password",
			body: map[string]interface{}{
				"email":              "testuser4@example.com",
				"display_name":       "Test User",
				"primary_login_type": "email",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "missing display_name",
			body: map[string]interface{}{
				"email":              "testuser5@example.com",
				"password":           "TestPass123!",
				"primary_login_type": "email",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "missing primary_login_type",
			body: map[string]interface{}{
				"email":        "testuser6@example.com",
				"password":     "TestPass123!",
				"display_name": "Test User",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "invalid email format",
			body: map[string]interface{}{
				"email":              "not-an-email",
				"password":           "TestPass123!",
				"display_name":       "Test User",
				"primary_login_type": "email",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "password too short",
			body: map[string]interface{}{
				"email":              "testuser7@example.com",
				"password":           "short",
				"display_name":       "Test User",
				"primary_login_type": "email",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "invalid primary_login_type",
			body: map[string]interface{}{
				"email":              "testuser8@example.com",
				"password":           "TestPass123!",
				"primary_login_type": "invalid",
				"display_name":       "Test User",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "invalid avatar_url",
			body: map[string]interface{}{
				"email":              "testuser9@example.com",
				"password":           "TestPass123!",
				"primary_login_type": "email",
				"display_name":       "Test User",
				"avatar_url":         "not-a-url",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "reject nonexistent roles on create",
			body: map[string]interface{}{
				"email":              "testuser10@example.com",
				"password":           "TestPass123!",
				"display_name":       "Test User",
				"primary_login_type": "email",
				"roles":              []string{"nonexistent"},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if !tt.wantErr {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.NotNil(t, response["data"])

				data := response["data"].(map[string]interface{})
				assert.NotNil(t, data["id"])

				// Verify email is in the response (from emails array)
				if tt.body["email"] != nil {
					emails := data["emails"].([]interface{})
					assert.NotEmpty(t, emails)
				}

				// Verify locale if provided
				if tt.body["locale"] != nil {
					assert.Equal(t, tt.body["locale"], data["locale"])
				}

				// Verify roles if provided
				if tt.body["roles"] != nil {
					roles := data["roles"].([]interface{})
					assert.Len(t, roles, len(tt.body["roles"].([]string)))
				}
			}
		})
	}
}

func TestHandler_ListUsers(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	// Create test users
	for i := 1; i <= 25; i++ {
		user := model.User{
			PrimaryLoginType: model.LoginTypeEmail,
			Status:           model.UserStatusActive,
		}
		require.NoError(t, db.Create(&user).Error)

		profile := model.UserProfile{
			UserID:      user.ID,
			DisplayName: "Test User",
			Locale:      "en_US",
		}
		require.NoError(t, db.Create(&profile).Error)

		email := model.UserEmail{
			UserID:    user.ID,
			Email:     fmt.Sprintf("test%d@example.com", i),
			IsPrimary: true,
		}
		require.NoError(t, db.Create(&email).Error)

		role := model.Role{Name: fmt.Sprintf("role-%d", i), DisplayName: fmt.Sprintf("Role %d", i), Description: "test role"}
		require.NoError(t, db.Create(&role).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: role.ID, GrantedBy: user.ID}).Error)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantCount  int
	}{
		{
			name:       "default pagination",
			query:      "",
			wantStatus: http.StatusOK,
			wantCount:  20,
		},
		{
			name:       "custom page size",
			query:      "?page=1&page_size=10",
			wantStatus: http.StatusOK,
			wantCount:  10,
		},
		{
			name:       "second page",
			query:      "?page=2&page_size=10",
			wantStatus: http.StatusOK,
			wantCount:  10,
		},
		{
			name:       "filter by status",
			query:      "?status=active",
			wantStatus: http.StatusOK,
			wantCount:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/users"+tt.query, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp response.Response
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			data, ok := resp.Data.(map[string]interface{})
			require.True(t, ok)
			items, ok := data["data"].([]interface{})
			require.True(t, ok)
			pagination, ok := data["pagination"].(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, tt.wantCount, len(items))
			assert.Equal(t, float64(25), pagination["total"])
			first := items[0].(map[string]interface{})
			assert.NotEmpty(t, first["roles"])
		})
	}
}

func TestHandler_UpdateUser(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	// Create test user
	user := model.User{
		PrimaryLoginType: model.LoginTypeEmail,
		Status:           model.UserStatusActive,
	}
	require.NoError(t, db.Create(&user).Error)

	profile := model.UserProfile{
		UserID:      user.ID,
		DisplayName: "Original Name",
		Locale:      "en_US",
	}
	require.NoError(t, db.Create(&profile).Error)

	email := model.UserEmail{
		UserID:    user.ID,
		Email:     "test@example.com",
		IsPrimary: true,
	}
	require.NoError(t, db.Create(&email).Error)

	roleUser := model.Role{Name: "user", DisplayName: "User", Description: "basic role"}
	roleAdmin := model.Role{Name: "admin", DisplayName: "Admin", Description: "admin role"}
	require.NoError(t, db.Create(&roleUser).Error)
	require.NoError(t, db.Create(&roleAdmin).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: roleUser.ID, GrantedBy: user.ID}).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		userID     uint64
		body       interface{}
		wantStatus int
	}{
		{
			name:   "update display name",
			userID: user.ID,
			body: map[string]interface{}{
				"display_name": "Updated Name",
			},
			wantStatus: http.StatusOK,
		},
		// Note: status, locale, and roles updates are not yet refactored to service layer
		// Use dedicated endpoints: PATCH /users/:id/status for status changes
		// These fields are ignored by the refactored UpdateUser endpoint
		{
			name:   "invalid user id",
			userID: 99999,
			body: map[string]interface{}{
				"display_name": "Name",
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "reject roles on update",
			userID: user.ID,
			body: map[string]interface{}{
				"roles": []string{"admin"},
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPatch, "/users/"+strconv.FormatUint(tt.userID, 10), bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestHandler_GetUserAggregatesRolesPermissionsAndSecurity(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&model.UserProfile{UserID: user.ID, DisplayName: "Aggregate User", Locale: "en_US"}).Error)
	require.NoError(t, db.Create(&model.UserEmail{UserID: user.ID, Email: "aggregate@example.com", IsPrimary: true}).Error)
	now := time.Now().UTC()
	require.NoError(t, db.Create(&model.UserSession{UserID: user.ID, AccessTokenHash: strings.Repeat("a", 64), RefreshTokenHash: strings.Repeat("b", 64), AccessExpiry: now.Add(time.Hour), RefreshExpiry: now.Add(24 * time.Hour)}).Error)
	require.NoError(t, db.Create(&model.UserTwoFactor{UserID: user.ID, Secret: "secret", EnabledAt: now}).Error)

	role := model.Role{Name: "auditor", DisplayName: "Auditor", Description: "auditor role"}
	permission := model.Permission{Name: model.PermAuditRead, Resource: model.ResourceAudit, Action: model.ActionRead, Description: "read audit logs"}
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&permission).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: role.ID, GrantedBy: user.ID}).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	req := httptest.NewRequest(http.MethodGet, "/users/"+strconv.FormatUint(user.ID, 10), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp response.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp.Data.(map[string]interface{})
	assert.Equal(t, []interface{}{"auditor"}, data["roles"])
	assert.Equal(t, []interface{}{model.PermAuditRead}, data["permissions"])
	assert.Equal(t, true, data["two_factor_enabled"])
	assert.Equal(t, float64(1), data["active_session_count"])
}

func TestHandler_PatchPrimaryRoleSupportsClearAndReturnsUnprocessableEntity(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	user := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	role := model.Role{Name: "member", DisplayName: "Member"}
	otherRole := model.Role{Name: "other", DisplayName: "Other"}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&role).Error)
	require.NoError(t, db.Create(&otherRole).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: user.ID, RoleID: role.ID, GrantedBy: user.ID}).Error)
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.ID).Update("primary_role_id", role.ID).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PATCH("/users/:id/primary-role", func(c *gin.Context) {
		c.Set("user_id", user.ID)
		handler.PatchPrimaryRole(c)
	})

	t.Run("clear primary role with null", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/users/"+strconv.FormatUint(user.ID, 10)+"/primary-role", bytes.NewBufferString(`{"primary_role_id":null}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var updated model.User
		require.NoError(t, db.First(&updated, user.ID).Error)
		assert.False(t, updated.PrimaryRoleID.Valid)
	})

	t.Run("reject role not assigned with 422", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/users/"+strconv.FormatUint(user.ID, 10)+"/primary-role", bytes.NewBufferString(`{"primary_role_id":`+strconv.FormatUint(otherRole.ID, 10)+`}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestHandler_DeleteUser(t *testing.T) {
	db := setupTestDB(t)
	handler := setupTestHandler(db)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		setupUser  bool
		hardDelete bool
		wantStatus int
	}{
		{
			name:       "soft delete user",
			setupUser:  true,
			hardDelete: false,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "hard delete user",
			setupUser:  true,
			hardDelete: true,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "delete non-existent user",
			setupUser:  false,
			hardDelete: false,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var userID uint64 = 99999

			if tt.setupUser {
				user := model.User{
					PrimaryLoginType: model.LoginTypeEmail,
					Status:           model.UserStatusActive,
				}
				require.NoError(t, db.Create(&user).Error)
				userID = user.ID

				profile := model.UserProfile{
					UserID:      user.ID,
					DisplayName: "Test User",
					Locale:      "en_US",
				}
				require.NoError(t, db.Create(&profile).Error)
			}

			url := "/users/" + strconv.FormatUint(userID, 10)
			if tt.hardDelete {
				url += "?hard_delete=true"
			}

			req := httptest.NewRequest(http.MethodDelete, url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.setupUser && tt.wantStatus == http.StatusNoContent {
				var deletedUser model.User
				if tt.hardDelete {
					err := db.Unscoped().First(&deletedUser, userID).Error
					assert.Error(t, err) // Should not exist
				} else {
					err := db.Unscoped().First(&deletedUser, userID).Error
					require.NoError(t, err)
					assert.NotNil(t, deletedUser.DeletedAt) // Should be soft deleted
				}
			}
		})
	}
}
