package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestHandler_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHandler(db)

	role := model.Role{Name: "user", DisplayName: "User", Description: "default user role"}
	require.NoError(t, db.Create(&role).Error)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		body       CreateUserRequest
		wantStatus int
		wantErr    bool
	}{
		{
			name: "valid user creation",
			body: CreateUserRequest{
				Email:       "test@example.com",
				DisplayName: "Test User",
				Password:    "Password123",
				Status:      "active",
				Roles:       []string{"user"},
			},
			wantStatus: http.StatusCreated,
			wantErr:    false,
		},
		{
			name: "role not found",
			body: CreateUserRequest{
				Email:       "missing-role@example.com",
				DisplayName: "Missing Role",
				Password:    "Password123",
				Roles:       []string{"missing"},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "duplicate email",
			body: CreateUserRequest{
				Email:       "test@example.com",
				DisplayName: "Another User",
				Password:    "Password123",
			},
			wantStatus: http.StatusConflict,
			wantErr:    true,
		},
		{
			name: "weak password",
			body: CreateUserRequest{
				Email:       "weak@example.com",
				DisplayName: "Weak User",
				Password:    "123",
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name: "invalid email",
			body: CreateUserRequest{
				Email:       "",
				DisplayName: "No Email User",
				Password:    "Password123",
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
				if roles, ok := data["roles"].([]interface{}); ok {
					assert.Equal(t, []interface{}{"user"}, roles)
				}
			}
		})
	}
}

func TestHandler_ListUsers(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHandler(db)

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
	handler := NewHandler(db)

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
		{
			name:   "update status",
			userID: user.ID,
			body: map[string]interface{}{
				"status": "suspended",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "update locale and roles",
			userID: user.ID,
			body: map[string]interface{}{
				"locale": "zh_CN",
				"roles":  []string{"admin"},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "clear roles",
			userID: user.ID,
			body: map[string]interface{}{
				"roles": []string{},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "invalid user id",
			userID: 99999,
			body: map[string]interface{}{
				"display_name": "Name",
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "invalid status",
			userID: user.ID,
			body: map[string]interface{}{
				"status": "invalid_status",
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

	var updatedProfile model.UserProfile
	require.NoError(t, db.Where("user_id = ?", user.ID).First(&updatedProfile).Error)
	assert.Equal(t, "zh_CN", updatedProfile.Locale)

	var userRoleCount int64
	require.NoError(t, db.Model(&model.UserRole{}).Where("user_id = ?", user.ID).Count(&userRoleCount).Error)
	assert.Zero(t, userRoleCount)
}

func TestHandler_GetUserAggregatesRolesPermissionsAndSecurity(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHandler(db)

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

func TestHandler_DeleteUser(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHandler(db)

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
			wantStatus: http.StatusOK,
		},
		{
			name:       "hard delete user",
			setupUser:  true,
			hardDelete: true,
			wantStatus: http.StatusOK,
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

			if tt.setupUser && tt.wantStatus == http.StatusOK {
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
