package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestSecurityHeadersMiddleware_SetsAllHeaders verifies that the four
// baseline security headers are emitted on every response.
// V10: Missing security response headers.
func TestSecurityHeadersMiddleware_SetsAllHeaders(t *testing.T) {
	engine := gin.New()
	engine.Use(SecurityHeaders(SecurityHeadersConfig{}))
	engine.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want %q", got, "no-referrer")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Errorf("Content-Security-Policy is empty, want non-empty default")
	}
}

// TestSecurityHeadersMiddleware_HSTSOnlyOverHTTPS verifies HSTS is only
// emitted when the request is over a TLS connection terminated in this
// process, or when AssumeHTTPS is opted into via config. A spoofed
// `X-Forwarded-Proto: https` from an untrusted client must NOT trigger
// HSTS — otherwise we risk pinning victim browsers out of plain-HTTP
// access to the host for the duration of max-age. V10.
func TestSecurityHeadersMiddleware_HSTSOnlyOverHTTPS(t *testing.T) {
	// 1. plain HTTP, AssumeHTTPS=false — HSTS must NOT be set.
	{
		engine := gin.New()
		engine.Use(SecurityHeaders(SecurityHeadersConfig{
			HSTSMaxAgeSeconds: 31536000,
		}))
		engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("plain HTTP: HSTS = %q, want empty", got)
		}
	}

	// 2. spoofed X-Forwarded-Proto: https from untrusted caller MUST
	// NOT cause HSTS to be emitted. This guards against the regression
	// flagged in C5 review (HSTS X-Forwarded-Proto bypass).
	{
		engine := gin.New()
		engine.Use(SecurityHeaders(SecurityHeadersConfig{
			HSTSMaxAgeSeconds: 31536000,
		}))
		engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("spoofed X-Forwarded-Proto: HSTS = %q, want empty (header is forgeable)", got)
		}
	}

	// 3. operator opts in via AssumeHTTPS — HSTS IS emitted.
	{
		engine := gin.New()
		engine.Use(SecurityHeaders(SecurityHeadersConfig{
			HSTSMaxAgeSeconds: 31536000,
			AssumeHTTPS:       true,
		}))
		engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		got := rec.Header().Get("Strict-Transport-Security")
		if got == "" {
			t.Fatalf("AssumeHTTPS=true: HSTS missing")
		}
		if !strings.Contains(got, "max-age=31536000") {
			t.Errorf("HSTS = %q, want to contain max-age=31536000", got)
		}
		if strings.Contains(got, "includeSubDomains") {
			t.Errorf("HSTS = %q, must not include subdomains by default", got)
		}
	}

	// 4. HSTSIncludeSub=true emits the directive.
	{
		engine := gin.New()
		engine.Use(SecurityHeaders(SecurityHeadersConfig{
			HSTSMaxAgeSeconds: 600,
			HSTSIncludeSub:    true,
			AssumeHTTPS:       true,
		}))
		engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		got := rec.Header().Get("Strict-Transport-Security")
		if !strings.Contains(got, "max-age=600") {
			t.Errorf("HSTS = %q, want max-age=600", got)
		}
		if !strings.Contains(got, "includeSubDomains") {
			t.Errorf("HSTS = %q, want includeSubDomains", got)
		}
	}
}

// TestSecurityHeadersMiddleware_CSPCustomizable verifies that a caller
// supplied CSP overrides the default. V10.
func TestSecurityHeadersMiddleware_CSPCustomizable(t *testing.T) {
	custom := "default-src 'none'; frame-ancestors 'none'"
	engine := gin.New()
	engine.Use(SecurityHeaders(SecurityHeadersConfig{CSP: custom}))
	engine.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Security-Policy"); got != custom {
		t.Errorf("Content-Security-Policy = %q, want %q", got, custom)
	}
}
