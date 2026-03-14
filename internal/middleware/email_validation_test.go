package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeAndValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid lowercase email",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "valid uppercase email - should normalize",
			input:    "User@Example.COM",
			expected: "user@example.com",
		},
		{
			name:     "valid mixed case - should normalize",
			input:    "UsEr@ExAmPlE.cOm",
			expected: "user@example.com",
		},
		{
			name:     "email with spaces - should trim and validate",
			input:    "  user@example.com  ",
			expected: "user@example.com",
		},
		{
			name:     "email with plus addressing",
			input:    "user+tag@example.com",
			expected: "user+tag@example.com",
		},
		{
			name:     "email with dots",
			input:    "first.last@example.com",
			expected: "first.last@example.com",
		},
		{
			name:     "invalid - no @",
			input:    "userexample.com",
			expected: "",
		},
		{
			name:     "invalid - no domain",
			input:    "user@",
			expected: "",
		},
		{
			name:     "invalid - no TLD",
			input:    "user@example",
			expected: "",
		},
		{
			name:     "invalid - empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid - only whitespace",
			input:    "   ",
			expected: "",
		},
		{
			name:     "invalid - special characters",
			input:    "user@exa mple.com",
			expected: "",
		},
		{
			name:     "invalid - too long (>254 chars)",
			input:    "a" + string(make([]byte, 250)) + "@example.com",
			expected: "",
		},
		{
			name:     "valid with subdomain",
			input:    "user@mail.example.com",
			expected: "user@mail.example.com",
		},
		{
			name:     "valid with hyphen",
			input:    "user@ex-ample.com",
			expected: "user@ex-ample.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeAndValidateEmail(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeAndValidateEmail(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEmailKeyFunc_Normalization(t *testing.T) {
	// Test that different case variations map to the same rate limit key
	email1 := normalizeAndValidateEmail("User@Example.com")
	email2 := normalizeAndValidateEmail("user@example.com")
	email3 := normalizeAndValidateEmail("USER@EXAMPLE.COM")

	if email1 == "" || email2 == "" || email3 == "" {
		t.Fatal("Valid emails should not return empty string")
	}

	if email1 != email2 || email2 != email3 {
		t.Errorf("Case variations should normalize to same email: %q, %q, %q", email1, email2, email3)
	}
}

func TestEmailKeyFunc_ExtractsEmailFromJSONBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/auth/forgot-password", strings.NewReader(`{"email":"User@Example.com"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.RemoteAddr = "192.168.1.1:12345"

	keyFunc := EmailKeyFunc("email")
	key := keyFunc(c)
	assert.Equal(t, "email:user@example.com", key)

	body := emailFromJSONBody(c, "email")
	assert.Equal(t, "User@Example.com", body)
}
