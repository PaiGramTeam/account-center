package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTOTPTimeWindowTolerance verifies that TOTP validation accepts codes
// from previous and next time windows (±30 seconds)
func TestTOTPTimeWindowTolerance(t *testing.T) {
	// Generate a TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestIssuer",
		AccountName: "test@example.com",
	})
	require.NoError(t, err)

	secret := key.Secret()
	now := time.Now()

	tests := []struct {
		name       string
		timePoint  time.Time
		shouldPass bool
	}{
		{
			name:       "current time window",
			timePoint:  now,
			shouldPass: true,
		},
		{
			name:       "previous time window (-30 seconds)",
			timePoint:  now.Add(-30 * time.Second),
			shouldPass: true,
		},
		{
			name:       "next time window (+30 seconds)",
			timePoint:  now.Add(30 * time.Second),
			shouldPass: true,
		},
		{
			name:       "2 windows ago (-60 seconds) - should fail",
			timePoint:  now.Add(-60 * time.Second),
			shouldPass: false,
		},
		{
			name:       "2 windows ahead (+60 seconds) - should fail",
			timePoint:  now.Add(60 * time.Second),
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate code for the specific time point
			code, err := totp.GenerateCode(secret, tt.timePoint)
			require.NoError(t, err)

			// Verify using current implementation
			// We validate against "now" but the code was generated for tt.timePoint
			result := verifyTOTP(code, secret)

			if tt.shouldPass {
				assert.True(t, result, "Code from %s should be accepted", tt.name)
			} else {
				assert.False(t, result, "Code from %s should be rejected", tt.name)
			}
		})
	}
}

// TestTOTPEdgeCases tests edge cases for TOTP validation
func TestTOTPEdgeCases(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestIssuer",
		AccountName: "test@example.com",
	})
	require.NoError(t, err)

	secret := key.Secret()

	t.Run("empty code", func(t *testing.T) {
		result := verifyTOTP("", secret)
		assert.False(t, result, "Empty code should be rejected")
	})

	t.Run("invalid code", func(t *testing.T) {
		result := verifyTOTP("000000", secret)
		// Very unlikely to match, but not guaranteed
		// Just verify it doesn't panic
		_ = result
	})

	t.Run("wrong length code", func(t *testing.T) {
		result := verifyTOTP("123", secret)
		assert.False(t, result, "Short code should be rejected")
	})

	t.Run("non-numeric code", func(t *testing.T) {
		result := verifyTOTP("abcdef", secret)
		assert.False(t, result, "Non-numeric code should be rejected")
	})
}

// BenchmarkTOTPVerification benchmarks TOTP verification performance
func BenchmarkTOTPVerification(b *testing.B) {
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestIssuer",
		AccountName: "test@example.com",
	})

	secret := key.Secret()
	code, _ := totp.GenerateCode(secret, time.Now())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifyTOTP(code, secret)
	}
}
