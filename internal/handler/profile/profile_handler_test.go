package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/model"
	"paigram/internal/testutil"
)

func setupTestDB(t *testing.T) *gorm.DB {
	return testutil.OpenMySQLTestDB(t, "profile", &model.User{}, &model.UserProfile{}, &model.UserEmail{}, &model.UserCredential{})
}

func createTestUser(t *testing.T, db *gorm.DB) *model.User {
	user := &model.User{
		ID:               1,
		PrimaryLoginType: model.LoginTypeEmail,
		Status:           model.UserStatusActive,
	}
	require.NoError(t, db.Create(user).Error)

	profile := &model.UserProfile{
		UserID:      user.ID,
		DisplayName: "Test User",
		Locale:      "en_US",
	}
	require.NoError(t, db.Create(profile).Error)

	email := &model.UserEmail{
		UserID:    user.ID,
		Email:     "test@example.com",
		IsPrimary: true,
	}
	require.NoError(t, db.Create(email).Error)

	// Create email credential
	emailCred := &model.UserCredential{
		UserID:            user.ID,
		Provider:          "email",
		ProviderAccountID: "test@example.com",
	}
	require.NoError(t, db.Create(emailCred).Error)

	return user
}

func TestHandler_GetBoundAccounts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("success - no bound accounts", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)
		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.GetBoundAccounts(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data, ok := response["data"].(map[string]interface{})
		require.True(t, ok)

		accounts, ok := data["data"].([]interface{})
		require.True(t, ok)
		assert.Empty(t, accounts)
	})

	t.Run("success - with bound accounts", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)

		// Add a Telegram credential
		metadata := map[string]interface{}{
			"display_name": "John Doe (@johndoe)",
			"avatar_url":   "",
		}
		metadataJSON, _ := json.Marshal(metadata)

		telegramCred := &model.UserCredential{
			UserID:            user.ID,
			Provider:          "telegram",
			ProviderAccountID: "123456789",
			Metadata:          string(metadataJSON),
		}
		require.NoError(t, db.Create(telegramCred).Error)

		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.GetBoundAccounts(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data, ok := response["data"].(map[string]interface{})
		require.True(t, ok)

		accounts, ok := data["data"].([]interface{})
		require.True(t, ok)
		assert.Len(t, accounts, 1)

		account := accounts[0].(map[string]interface{})
		assert.Equal(t, "telegram", account["provider"])
		assert.Equal(t, "123456789", account["provider_account_id"])
		assert.Equal(t, "John Doe (@johndoe)", account["display_name"])
	})

	t.Run("invalid user ID", func(t *testing.T) {
		db := setupTestDB(t)
		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{{Key: "id", Value: "invalid"}}

		handler.GetBoundAccounts(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("user not found", func(t *testing.T) {
		db := setupTestDB(t)
		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{{Key: "id", Value: "999"}}

		handler.GetBoundAccounts(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandler_BindAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("success - bind telegram account", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)
		handler := NewHandler(db, config.AuthConfig{})

		reqBody := bindAccountRequest{
			Provider: "telegram",
			ProviderData: map[string]interface{}{
				"id":         float64(123456789),
				"first_name": "John",
				"last_name":  "Doe",
				"username":   "johndoe",
			},
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.BindAccount(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data, ok := response["data"].(map[string]interface{})
		require.True(t, ok)

		responseData, ok := data["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "telegram", responseData["provider"])
		assert.Equal(t, "123456789", responseData["provider_account_id"])
		assert.Equal(t, "John Doe (@johndoe)", responseData["display_name"])

		// Verify credential was created in DB
		var cred model.UserCredential
		err = db.Where("user_id = ? AND provider = ?", user.ID, "telegram").First(&cred).Error
		require.NoError(t, err)
		assert.Equal(t, "123456789", cred.ProviderAccountID)
	})

	t.Run("invalid provider", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)
		handler := NewHandler(db, config.AuthConfig{})

		reqBody := bindAccountRequest{
			Provider: "invalid_provider",
			ProviderData: map[string]interface{}{
				"id": "123",
			},
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.BindAccount(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("provider already bound", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)

		// Pre-create a telegram credential
		telegramCred := &model.UserCredential{
			UserID:            user.ID,
			Provider:          "telegram",
			ProviderAccountID: "123456789",
		}
		require.NoError(t, db.Create(telegramCred).Error)

		handler := NewHandler(db, config.AuthConfig{})

		reqBody := bindAccountRequest{
			Provider: "telegram",
			ProviderData: map[string]interface{}{
				"id": float64(123456789),
			},
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.BindAccount(c)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("missing provider account ID", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)
		handler := NewHandler(db, config.AuthConfig{})

		reqBody := bindAccountRequest{
			Provider: "telegram",
			ProviderData: map[string]interface{}{
				"first_name": "John",
			},
		}
		body, _ := json.Marshal(reqBody)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = []gin.Param{{Key: "id", Value: fmt.Sprintf("%d", user.ID)}}

		handler.BindAccount(c)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_UnbindAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("success - unbind account", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)

		// Create a telegram credential
		telegramCred := &model.UserCredential{
			UserID:            user.ID,
			Provider:          "telegram",
			ProviderAccountID: "123456789",
		}
		require.NoError(t, db.Create(telegramCred).Error)

		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{
			{Key: "id", Value: fmt.Sprintf("%d", user.ID)},
			{Key: "provider", Value: "telegram"},
		}

		handler.UnbindAccount(c)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify credential was deleted
		var count int64
		db.Model(&model.UserCredential{}).Where("user_id = ? AND provider = ?", user.ID, "telegram").Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("cannot remove last login method", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)

		// Remove the email credential first
		db.Where("user_id = ? AND provider = ?", user.ID, "email").Delete(&model.UserCredential{})

		// Create only one credential (telegram)
		telegramCred := &model.UserCredential{
			UserID:            user.ID,
			Provider:          "telegram",
			ProviderAccountID: "123456789",
		}
		require.NoError(t, db.Create(telegramCred).Error)

		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{
			{Key: "id", Value: fmt.Sprintf("%d", user.ID)},
			{Key: "provider", Value: "telegram"},
		}

		handler.UnbindAccount(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("provider not bound", func(t *testing.T) {
		db := setupTestDB(t)
		user := createTestUser(t, db)
		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{
			{Key: "id", Value: fmt.Sprintf("%d", user.ID)},
			{Key: "provider", Value: "telegram"},
		}

		handler.UnbindAccount(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("user not found", func(t *testing.T) {
		db := setupTestDB(t)
		handler := NewHandler(db, config.AuthConfig{})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = []gin.Param{
			{Key: "id", Value: "999"},
			{Key: "provider", Value: "telegram"},
		}

		handler.UnbindAccount(c)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
