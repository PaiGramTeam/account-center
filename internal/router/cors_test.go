package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

func TestNewCORSMiddlewareAllowsConfiguredOrigin(t *testing.T) {
	engine := newTestCORSEngine(t, config.CORSConfig{
		Enabled:          true,
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAgeSeconds:    600,
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
}

func TestNewCORSMiddlewareHandlesPreflight(t *testing.T) {
	engine := newTestCORSEngine(t, config.CORSConfig{
		Enabled:       true,
		AllowOrigins:  []string{"http://localhost:5173"},
		AllowMethods:  []string{"GET", "POST", "PATCH", "OPTIONS"},
		AllowHeaders:  []string{"Authorization", "Content-Type"},
		MaxAgeSeconds: 1200,
	})

	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", http.MethodPatch)
	req.Header.Set("Access-Control-Request-Headers", "Authorization,Content-Type")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET,POST,PATCH,OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	assert.Equal(t, "1200", w.Header().Get("Access-Control-Max-Age"))
}

func TestNewCORSMiddlewareRejectsUnknownOrigin(t *testing.T) {
	engine := newTestCORSEngine(t, config.CORSConfig{
		Enabled:      true,
		AllowOrigins: []string{"http://localhost:3000"},
		AllowMethods: []string{"GET", "OPTIONS"},
		AllowHeaders: []string{"Content-Type"},
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "http://malicious.example")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestNewCORSMiddlewareRejectsWildcardCredentialsCombination(t *testing.T) {
	_, err := newCORSMiddleware(config.CORSConfig{
		Enabled:          true,
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow_credentials")
}

func newTestCORSEngine(t *testing.T, corsCfg config.CORSConfig) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	middleware, err := newCORSMiddleware(corsCfg)
	require.NoError(t, err)
	require.NotNil(t, middleware)

	engine.Use(middleware)
	engine.Any("/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return engine
}
