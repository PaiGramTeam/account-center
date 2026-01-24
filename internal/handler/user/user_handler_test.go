package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"paigram/internal/model"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&model.User{},
		&model.UserProfile{},
		&model.UserCredential{},
		&model.UserEmail{},
		&model.UserSession{},
	)
	require.NoError(t, err)

	return db
}

func TestHandler_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	handler := NewHandler(db)

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
			},
			wantStatus: http.StatusCreated,
			wantErr:    false,
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
			Email:     "test" + string(rune(i)) + "@example.com",
			IsPrimary: true,
		}
		require.NoError(t, db.Create(&email).Error)
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

			var response UserListResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, len(response.Data))
			assert.Equal(t, int64(25), response.Pagination.Total)
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

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router.Group("/users"))

	tests := []struct {
		name       string
		userID     uint64
		body       UpdateUserRequest
		wantStatus int
	}{
		{
			name:   "update display name",
			userID: user.ID,
			body: UpdateUserRequest{
				DisplayName: "Updated Name",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "update status",
			userID: user.ID,
			body: UpdateUserRequest{
				Status: "suspended",
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "invalid user id",
			userID: 99999,
			body: UpdateUserRequest{
				DisplayName: "Name",
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "invalid status",
			userID: user.ID,
			body: UpdateUserRequest{
				Status: "invalid_status",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPatch, "/users/"+string(rune(tt.userID)), bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
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

			url := "/users/" + string(rune(userID))
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
