package email

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/config"
)

// mockSender is a mock email sender for testing
type mockSender struct {
	sendFunc func(ctx context.Context, msg *Message) error
	calls    []*Message
}

func (m *mockSender) Send(ctx context.Context, msg *Message) error {
	m.calls = append(m.calls, msg)
	if m.sendFunc != nil {
		return m.sendFunc(ctx, msg)
	}
	return nil
}

func TestNewService(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.EmailConfig
		wantErr bool
	}{
		{
			name: "disabled service",
			cfg: config.EmailConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid SMTP config",
			cfg: config.EmailConfig{
				Enabled:      true,
				Provider:     "smtp",
				SMTPHost:     "smtp.example.com",
				SMTPPort:     587,
				FromEmail:    "noreply@example.com",
				FromName:     "Test",
				SMTPUsername: "user",
				SMTPPassword: "pass",
			},
			wantErr: false,
		},
		{
			name: "invalid provider",
			cfg: config.EmailConfig{
				Enabled:  true,
				Provider: "invalid",
			},
			wantErr: true,
		},
		{
			name: "missing SMTP host",
			cfg: config.EmailConfig{
				Enabled:  true,
				Provider: "smtp",
				SMTPPort: 587,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, svc)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, svc)
			}
		})
	}
}

func TestService_Send(t *testing.T) {
	mock := &mockSender{}
	svc := &Service{
		cfg: config.EmailConfig{
			Enabled: true,
		},
		sender:      mock,
		rateLimiter: &NoopRateLimiter{},
	}

	msg := &Message{
		To:       []string{"test@example.com"},
		Subject:  "Test Subject",
		TextBody: "Test body",
		Priority: PriorityNormal,
	}

	err := svc.Send(context.Background(), msg)
	require.NoError(t, err)
	assert.Len(t, mock.calls, 1)
	assert.Equal(t, msg, mock.calls[0])
}

func TestService_SendAsync(t *testing.T) {
	mock := &mockSender{}
	queue := NewMemoryQueue(mock, config.EmailConfig{
		QueueSize:     100,
		RetryAttempts: 1,
		RetryDelay:    1,
	})

	svc := &Service{
		cfg: config.EmailConfig{
			Enabled:       true,
			UseAsyncQueue: true,
		},
		sender:      mock,
		queue:       queue,
		rateLimiter: &NoopRateLimiter{},
	}

	ctx := context.Background()
	err := queue.Start(ctx)
	require.NoError(t, err)
	defer queue.Stop()

	msg := &Message{
		To:       []string{"test@example.com"},
		Subject:  "Test Subject",
		TextBody: "Test body",
		Priority: PriorityHigh,
	}

	err = svc.SendAsync(ctx, msg)
	require.NoError(t, err)

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	assert.Eventually(t, func() bool {
		return len(mock.calls) == 1
	}, 2*time.Second, 100*time.Millisecond)
}

func TestTemplateData_Validate(t *testing.T) {
	tests := []struct {
		name    string
		data    TemplateData
		wantErr bool
	}{
		{
			name: "valid email verification data",
			data: &EmailVerificationData{
				VerifyURL: "https://example.com/verify",
				Token:     "abc123",
			},
			wantErr: false,
		},
		{
			name: "missing verify URL",
			data: &EmailVerificationData{
				Token: "abc123",
			},
			wantErr: true,
		},
		{
			name: "missing token",
			data: &EmailVerificationData{
				VerifyURL: "https://example.com/verify",
			},
			wantErr: true,
		},
		{
			name: "valid password reset data",
			data: &PasswordResetData{
				ResetURL: "https://example.com/reset",
			},
			wantErr: false,
		},
		{
			name:    "missing reset URL",
			data:    &PasswordResetData{},
			wantErr: true,
		},
		{
			name: "valid new device login data",
			data: &NewDeviceLoginData{
				DeviceName: "Chrome on Windows",
				IP:         "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "missing device name",
			data: &NewDeviceLoginData{
				IP: "192.168.1.1",
			},
			wantErr: true,
		},
		{
			name: "valid 2FA backup codes data",
			data: &TwoFactorBackupCodesData{
				BackupCodes: []string{"code1", "code2"},
			},
			wantErr: false,
		},
		{
			name:    "empty backup codes",
			data:    &TwoFactorBackupCodesData{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.data.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRenderTemplate(t *testing.T) {
	svc, err := NewService(config.EmailConfig{
		Enabled: false,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		template string
		data     interface{}
		wantErr  bool
	}{
		{
			name:     "valid email verification template",
			template: "email_verification",
			data: &EmailVerificationData{
				VerifyURL: "https://example.com/verify",
				Token:     "abc123",
			},
			wantErr: false,
		},
		{
			name:     "valid password reset template",
			template: "password_reset",
			data: &PasswordResetData{
				ResetURL: "https://example.com/reset",
			},
			wantErr: false,
		},
		{
			name:     "template not found",
			template: "nonexistent",
			data:     map[string]string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := svc.renderTemplate(tt.template, tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
				assert.Contains(t, result, "<!DOCTYPE html>")
			}
		})
	}
}

func TestPriorityQueue(t *testing.T) {
	mock := &mockSender{}
	queue := NewMemoryQueue(mock, config.EmailConfig{
		QueueSize:     100,
		RetryAttempts: 0,
		RetryDelay:    1,
	})

	ctx := context.Background()
	err := queue.Start(ctx)
	require.NoError(t, err)
	defer queue.Stop()

	// Enqueue messages with different priorities
	lowPriorityMsg := &Message{
		To:       []string{"low@example.com"},
		Subject:  "Low Priority",
		TextBody: "Low",
		Priority: PriorityLow,
	}
	highPriorityMsg := &Message{
		To:       []string{"high@example.com"},
		Subject:  "High Priority",
		TextBody: "High",
		Priority: PriorityHigh,
	}
	normalPriorityMsg := &Message{
		To:       []string{"normal@example.com"},
		Subject:  "Normal Priority",
		TextBody: "Normal",
		Priority: PriorityNormal,
	}

	// Enqueue in random order
	require.NoError(t, queue.Enqueue(ctx, lowPriorityMsg))
	require.NoError(t, queue.Enqueue(ctx, highPriorityMsg))
	require.NoError(t, queue.Enqueue(ctx, normalPriorityMsg))

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// High priority should be sent first
	assert.Eventually(t, func() bool {
		return len(mock.calls) == 3
	}, 2*time.Second, 100*time.Millisecond)

	if len(mock.calls) >= 1 {
		assert.Equal(t, "High Priority", mock.calls[0].Subject)
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewTokenBucketLimiter(1.0, 2) // 1 per second, burst of 2

	// First two should succeed (burst)
	assert.True(t, limiter.Allow("test@example.com"))
	assert.True(t, limiter.Allow("test@example.com"))

	// Third should fail (rate limited)
	assert.False(t, limiter.Allow("test@example.com"))

	// Different key should succeed
	assert.True(t, limiter.Allow("other@example.com"))
}

func TestMessagePriority(t *testing.T) {
	tests := []struct {
		priority Priority
		expected string
	}{
		{PriorityLow, "low"},
		{PriorityNormal, "normal"},
		{PriorityHigh, "high"},
		{PriorityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, priorityString(tt.priority))
		})
	}
}
