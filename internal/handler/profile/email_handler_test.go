package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/handler/shared"
	"paigram/internal/model"
)

func setupTestDBForEmail(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.User{}, &model.UserProfile{}, &model.UserEmail{}, &model.UserCredential{})
	require.NoError(t, err)

	// Create test user
	user := model.User{
		ID:               1,
		PrimaryLoginType: model.LoginTypeEmail,
		Status:           model.UserStatusActive,
	}
	err = db.Create(&user).Error
	require.NoError(t, err)

	// Create user profile
	profile := model.UserProfile{
		UserID:      1,
		DisplayName: "Test User",
		Locale:      "en_US",
	}
	err = db.Create(&profile).Error
	require.NoError(t, err)

	// Create primary email
	primaryEmail := model.UserEmail{
		UserID:     1,
		Email:      "primary@example.com",
		IsPrimary:  true,
		VerifiedAt: shared.MakeNullTime(time.Now()),
	}
	err = db.Create(&primaryEmail).Error
	require.NoError(t, err)

	// Create credential
	credential := model.UserCredential{
		UserID:            1,
		Provider:          "email",
		ProviderAccountID: "primary@example.com",
		PasswordHash:      "hashed_password",
	}
	err = db.Create(&credential).Error
	require.NoError(t, err)

	return db
}

func TestEmailHandler_AddEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDBForEmail(t)
	cfg := config.AuthConfig{
		EmailVerificationTTLSeconds: 86400, // 24 hours
	}
	handler := NewEmailHandler(db, cfg)

	tests := []struct {
		name           string
		userID         string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
		setup          func()
	}{
		{
			name:   "successful_add_email",
			userID: "1",
			requestBody: map[string]string{
				"email": "new@example.com",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:   "invalid_user_id",
			userID: "invalid",
			requestBody: map[string]string{
				"email": "new@example.com",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid user id",
		},
		{
			name:           "invalid_email_format",
			userID:         "1",
			requestBody:    map[string]string{"email": "not-an-email"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid email format",
		},
		{
			name:           "email_already_exists_same_user",
			userID:         "1",
			requestBody:    map[string]string{"email": "primary@example.com"},
			expectedStatus: http.StatusConflict,
			expectedError:  "email already added to this account",
		},
		{
			name:   "email_already_exists_different_user",
			userID: "1",
			requestBody: map[string]string{
				"email": "other@example.com",
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "email already in use by another account",
			setup: func() {
				// Create another user with this email
				user := model.User{ID: 2, PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
				db.Create(&user)
				email := model.UserEmail{UserID: 2, Email: "other@example.com", IsPrimary: true}
				db.Create(&email)
			},
		},
		{
			name:           "user_not_found",
			userID:         "999",
			requestBody:    map[string]string{"email": "new@example.com"},
			expectedStatus: http.StatusNotFound,
			expectedError:  "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			router := gin.New()
			router.POST("/profiles/:id/emails", handler.AddEmail)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", fmt.Sprintf("/profiles/%s/emails", tt.userID), bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				if errorObj, ok := response["error"].(map[string]interface{}); ok {
					assert.Contains(t, errorObj["message"], tt.expectedError)
				} else {
					assert.Contains(t, response["message"], tt.expectedError)
				}
			}

			if tt.expectedStatus == http.StatusCreated {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				data, ok := response["data"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, tt.requestBody.(map[string]string)["email"], data["email"])
				assert.False(t, data["is_primary"].(bool))
				assert.NotEmpty(t, data["verification_token"])
				assert.NotEmpty(t, data["verification_expires_at"])
			}
		})
	}
}

func TestEmailHandler_DeleteEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userID         string
		email          string
		expectedStatus int
		expectedError  string
		setup          func(db *gorm.DB)
	}{
		{
			name:           "successful_delete_non_primary",
			userID:         "1",
			email:          "secondary@example.com",
			expectedStatus: http.StatusOK,
			setup: func(db *gorm.DB) {
				// Add secondary email
				email := model.UserEmail{
					UserID:     1,
					Email:      "secondary@example.com",
					IsPrimary:  false,
					VerifiedAt: shared.MakeNullTime(time.Now()),
				}
				db.Create(&email)
			},
		},
		{
			name:           "cannot_delete_only_email",
			userID:         "1",
			email:          "only@example.com",
			expectedStatus: http.StatusForbidden,
			expectedError:  "cannot delete the only email",
			setup: func(db *gorm.DB) {
				// Delete all emails and create only one
				db.Where("user_id = ?", 1).Delete(&model.UserEmail{})
				email := model.UserEmail{
					UserID:     1,
					Email:      "only@example.com",
					IsPrimary:  true,
					VerifiedAt: shared.MakeNullTime(time.Now()),
				}
				db.Create(&email)
			},
		},
		{
			name:           "delete_primary_email_promotes_other",
			userID:         "1",
			email:          "primary@example.com",
			expectedStatus: http.StatusOK,
			setup: func(db *gorm.DB) {
				// Add secondary email
				email := model.UserEmail{
					UserID:     1,
					Email:      "secondary@example.com",
					IsPrimary:  false,
					VerifiedAt: shared.MakeNullTime(time.Now()),
				}
				db.Create(&email)
			},
		},
		{
			name:           "email_not_found",
			userID:         "1",
			email:          "notfound@example.com",
			expectedStatus: http.StatusNotFound,
			expectedError:  "email not found",
		},
		{
			name:           "invalid_user_id",
			userID:         "invalid",
			email:          "test@example.com",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid user id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDBForEmail(t)
			if tt.setup != nil {
				tt.setup(db)
			}

			cfg := config.AuthConfig{}
			handler := NewEmailHandler(db, cfg)

			router := gin.New()
			router.DELETE("/profiles/:id/emails/:email", handler.DeleteEmail)

			req := httptest.NewRequest("DELETE", fmt.Sprintf("/profiles/%s/emails/%s", tt.userID, tt.email), nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				if errorObj, ok := response["error"].(map[string]interface{}); ok {
					assert.Contains(t, errorObj["message"], tt.expectedError)
				} else {
					assert.Contains(t, response["message"], tt.expectedError)
				}
			}

			// Verify primary email promotion
			if tt.name == "delete_primary_email_promotes_other" && tt.expectedStatus == http.StatusOK {
				var secondaryEmail model.UserEmail
				err := db.Where("email = ?", "secondary@example.com").First(&secondaryEmail).Error
				require.NoError(t, err)
				assert.True(t, secondaryEmail.IsPrimary)
			}
		})
	}
}

func TestEmailHandler_SetPrimaryEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userID         string
		email          string
		expectedStatus int
		expectedError  string
		setup          func(db *gorm.DB)
	}{
		{
			name:           "successful_set_primary",
			userID:         "1",
			email:          "secondary@example.com",
			expectedStatus: http.StatusOK,
			setup: func(db *gorm.DB) {
				// Add verified secondary email
				email := model.UserEmail{
					UserID:     1,
					Email:      "secondary@example.com",
					IsPrimary:  false,
					VerifiedAt: shared.MakeNullTime(time.Now()),
				}
				db.Create(&email)
			},
		},
		{
			name:           "email_not_verified",
			userID:         "1",
			email:          "unverified@example.com",
			expectedStatus: http.StatusForbidden,
			expectedError:  "email must be verified before setting as primary",
			setup: func(db *gorm.DB) {
				// Add unverified email
				email := model.UserEmail{
					UserID:    1,
					Email:     "unverified@example.com",
					IsPrimary: false,
				}
				db.Create(&email)
			},
		},
		{
			name:           "email_not_found",
			userID:         "1",
			email:          "notfound@example.com",
			expectedStatus: http.StatusNotFound,
			expectedError:  "email not found",
		},
		{
			name:           "already_primary",
			userID:         "1",
			email:          "primary@example.com",
			expectedStatus: http.StatusOK, // Success even if already primary
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDBForEmail(t)
			if tt.setup != nil {
				tt.setup(db)
			}

			cfg := config.AuthConfig{}
			handler := NewEmailHandler(db, cfg)

			router := gin.New()
			router.PATCH("/profiles/:id/emails/:email/primary", handler.SetPrimaryEmail)

			req := httptest.NewRequest("PATCH", fmt.Sprintf("/profiles/%s/emails/%s/primary", tt.userID, tt.email), nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				if errorObj, ok := response["error"].(map[string]interface{}); ok {
					assert.Contains(t, errorObj["message"], tt.expectedError)
				}
			}

			// Verify primary email change
			if tt.name == "successful_set_primary" && tt.expectedStatus == http.StatusOK {
				var emails []model.UserEmail
				err := db.Where("user_id = ?", 1).Find(&emails).Error
				require.NoError(t, err)

				primaryCount := 0
				for _, email := range emails {
					if email.IsPrimary {
						primaryCount++
						assert.Equal(t, "secondary@example.com", email.Email)
					}
				}
				assert.Equal(t, 1, primaryCount)
			}
		})
	}
}

func TestEmailHandler_ResendVerificationEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		userID         string
		email          string
		expectedStatus int
		expectedError  string
		setup          func(db *gorm.DB)
		wait           time.Duration
	}{
		{
			name:           "successful_resend",
			userID:         "1",
			email:          "unverified@example.com",
			expectedStatus: http.StatusOK,
			setup: func(db *gorm.DB) {
				// Add unverified email with old timestamp
				email := model.UserEmail{
					UserID:             1,
					Email:              "unverified@example.com",
					IsPrimary:          false,
					VerificationToken:  "old_token",
					VerificationExpiry: shared.MakeNullTime(time.Now().Add(-time.Hour)),
					CreatedAt:          time.Now().Add(-2 * time.Minute),
					UpdatedAt:          time.Now().Add(-2 * time.Minute),
				}
				db.Create(&email)
			},
		},
		{
			name:           "rate_limited",
			userID:         "1",
			email:          "recent@example.com",
			expectedStatus: 429,
			expectedError:  "please wait before requesting another verification email",
			setup: func(db *gorm.DB) {
				// Add unverified email with recent timestamp
				email := model.UserEmail{
					UserID:    1,
					Email:     "recent@example.com",
					IsPrimary: false,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				db.Create(&email)
			},
		},
		{
			name:           "already_verified",
			userID:         "1",
			email:          "verified@example.com",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email is already verified",
			setup: func(db *gorm.DB) {
				// Add verified email
				email := model.UserEmail{
					UserID:     1,
					Email:      "verified@example.com",
					IsPrimary:  false,
					VerifiedAt: shared.MakeNullTime(time.Now()),
				}
				db.Create(&email)
			},
		},
		{
			name:           "email_not_found",
			userID:         "1",
			email:          "notfound@example.com",
			expectedStatus: http.StatusNotFound,
			expectedError:  "email not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDBForEmail(t)
			if tt.setup != nil {
				tt.setup(db)
			}

			cfg := config.AuthConfig{
				EmailVerificationTTLSeconds: 86400, // 24 hours
			}
			handler := NewEmailHandler(db, cfg)

			router := gin.New()
			router.POST("/profiles/:id/emails/:email/verify", handler.ResendVerificationEmail)

			req := httptest.NewRequest("POST", fmt.Sprintf("/profiles/%s/emails/%s/verify", tt.userID, tt.email), nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				if errorObj, ok := response["error"].(map[string]interface{}); ok {
					assert.Contains(t, errorObj["message"], tt.expectedError)
				} else {
					assert.Contains(t, response["message"], tt.expectedError)
				}
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)

				data, ok := response["data"].(map[string]interface{})
				require.True(t, ok)
				assert.Contains(t, data["message"], "verification email sent successfully")
				assert.NotEmpty(t, data["verification_expires_at"])

				// Verify token was updated
				var email model.UserEmail
				err = db.Where("email = ?", tt.email).First(&email).Error
				require.NoError(t, err)
				assert.NotEqual(t, "old_token", email.VerificationToken)
				assert.NotEmpty(t, email.VerificationToken)
			}
		})
	}
}
