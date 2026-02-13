package email

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"paigram/internal/config"
	"paigram/internal/logging"
)

// Service handles email sending functionality
type Service struct {
	cfg             config.EmailConfig
	sender          Sender
	queue           Queue
	rateLimiter     RateLimiter
	templateManager *TemplateManager
	redisClient     *redis.Client // Redis client for queue (optional)
}

// Sender defines the interface for sending emails
type Sender interface {
	Send(ctx context.Context, msg *Message) error
}

// Queue defines the interface for async email queue
type Queue interface {
	Enqueue(ctx context.Context, msg *Message) error
	Start(ctx context.Context) error
	Stop() error
}

// Message represents an email message
type Message struct {
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	TextBody    string
	HTMLBody    string
	Attachments []Attachment
	Priority    Priority // Email priority
}

// Priority defines email priority levels
type Priority int

const (
	PriorityLow Priority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// Attachment represents an email attachment
type Attachment struct {
	Filename string
	Content  []byte
	MimeType string
}

// NewService creates a new email service without Redis queue support
// For Redis queue support, use NewServiceWithRedis
func NewService(cfg config.EmailConfig) (*Service, error) {
	return NewServiceWithRedis(cfg, nil)
}

// NewServiceWithRedis creates a new email service with optional Redis queue support
func NewServiceWithRedis(cfg config.EmailConfig, redisClient *redis.Client) (*Service, error) {
	// Initialize template manager
	templateManager, err := NewTemplateManager(cfg.TemplateDir)
	if err != nil {
		return nil, fmt.Errorf("create template manager: %w", err)
	}

	if !cfg.Enabled {
		return &Service{
			cfg:             cfg,
			sender:          &NoopSender{},
			queue:           &NoopQueue{},
			rateLimiter:     &NoopRateLimiter{},
			templateManager: templateManager,
			redisClient:     redisClient,
		}, nil
	}

	var sender Sender

	switch cfg.Provider {
	case "smtp":
		sender, err = NewSMTPSender(cfg)
		if err != nil {
			return nil, fmt.Errorf("create SMTP sender: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported email provider: %s", cfg.Provider)
	}

	var queue Queue
	if cfg.UseAsyncQueue {
		// Determine queue backend
		queueBackend := cfg.QueueBackend
		if queueBackend == "" {
			queueBackend = "memory" // Default to memory for backward compatibility
		}

		switch queueBackend {
		case "redis":
			if redisClient == nil {
				return nil, fmt.Errorf("redis queue backend requires redis client")
			}
			queue = NewRedisQueue(redisClient, sender, cfg)
			logging.Info("using redis queue backend for emails")
		case "memory":
			queue = NewMemoryQueue(sender, cfg)
			logging.Info("using memory queue backend for emails")
		default:
			return nil, fmt.Errorf("unsupported queue backend: %s (supported: memory, redis)", queueBackend)
		}
	} else {
		queue = &NoopQueue{}
	}

	// Create rate limiter: 10 emails per second per recipient, burst of 20
	rateLimiter := NewTokenBucketLimiter(10.0, 20)

	return &Service{
		cfg:             cfg,
		sender:          sender,
		queue:           queue,
		rateLimiter:     rateLimiter,
		templateManager: templateManager,
		redisClient:     redisClient,
	}, nil
}

// Send sends an email immediately
func (s *Service) Send(ctx context.Context, msg *Message) error {
	if !s.cfg.Enabled {
		logging.Info("email service disabled, skipping send",
			zap.Strings("to", msg.To),
			zap.String("subject", msg.Subject),
		)
		return nil
	}

	start := time.Now()
	err := s.sender.Send(ctx, msg)
	duration := time.Since(start).Seconds()

	// Record metrics
	status := "success"
	if err != nil {
		status = "error"
	}
	EmailsSentTotal.WithLabelValues(status, priorityString(msg.Priority)).Inc()
	EmailSendDuration.WithLabelValues(status).Observe(duration)

	return err
}

// SendAsync sends an email asynchronously via queue
func (s *Service) SendAsync(ctx context.Context, msg *Message) error {
	if !s.cfg.Enabled {
		logging.Info("email service disabled, skipping async send",
			zap.Strings("to", msg.To),
			zap.String("subject", msg.Subject),
		)
		return nil
	}

	// Check rate limit for each recipient
	for _, recipient := range msg.To {
		if !s.rateLimiter.Allow(recipient) {
			EmailRateLimitExceeded.WithLabelValues(recipient).Inc()
			return fmt.Errorf("rate limit exceeded for recipient: %s", recipient)
		}
	}

	if !s.cfg.UseAsyncQueue {
		// Fallback to sync send
		return s.Send(ctx, msg)
	}

	return s.queue.Enqueue(ctx, msg)
}

// StartQueue starts the async queue processor
func (s *Service) StartQueue(ctx context.Context) error {
	if !s.cfg.UseAsyncQueue {
		return nil
	}
	return s.queue.Start(ctx)
}

// StopQueue stops the async queue processor
func (s *Service) StopQueue() error {
	if !s.cfg.UseAsyncQueue {
		return nil
	}
	return s.queue.Stop()
}

// Close gracefully shuts down the email service
func (s *Service) Close() error {
	return s.StopQueue()
}

// SendVerificationEmail sends an email verification email
func (s *Service) SendVerificationEmail(ctx context.Context, to, token, baseURL string) error {
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", baseURL, token)

	data := &EmailVerificationData{
		VerifyURL: verifyURL,
		Token:     token,
	}

	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("email_verification", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := fmt.Sprintf(`
Welcome to PaiGram!

Please verify your email address by clicking the link below:
%s

Or enter this verification code: %s

This link will expire in 24 hours.

If you did not create an account, please ignore this email.
`, verifyURL, token)

	msg := &Message{
		To:       []string{to},
		Subject:  "Verify Your Email Address",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityHigh, // Verification emails are high priority
	}

	return s.SendAsync(ctx, msg)
}

// SendPasswordResetEmail sends a password reset email
func (s *Service) SendPasswordResetEmail(ctx context.Context, to, token, baseURL string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)

	data := &PasswordResetData{
		ResetURL: resetURL,
	}

	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("password_reset", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := fmt.Sprintf(`
Password Reset Request

We received a request to reset your password. Click the link below to reset it:
%s

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email or contact support if you have concerns.
`, resetURL)

	msg := &Message{
		To:       []string{to},
		Subject:  "Reset Your Password",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityHigh, // Password reset is high priority
	}

	return s.SendAsync(ctx, msg)
}

// SendPasswordChangedEmail sends a notification when password is changed
func (s *Service) SendPasswordChangedEmail(ctx context.Context, to string) error {
	data := &PasswordChangedData{
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("password_changed", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := `
Your Password Has Been Changed

This email confirms that your password was successfully changed.

If you did not make this change, please contact support immediately.
`

	msg := &Message{
		To:       []string{to},
		Subject:  "Your Password Has Been Changed",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityNormal,
	}

	return s.SendAsync(ctx, msg)
}

// SendNewDeviceLoginEmail sends a notification for new device login
func (s *Service) SendNewDeviceLoginEmail(ctx context.Context, to, deviceName, location, ip string) error {
	data := &NewDeviceLoginData{
		DeviceName: deviceName,
		Location:   location,
		IP:         ip,
		Timestamp:  time.Now().Format("2006-01-02 15:04:05 MST"),
	}

	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("new_device_login", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := fmt.Sprintf(`
New Device Login Detected

A new device has logged into your account:

Device: %s
Location: %s
IP Address: %s
Time: %s

If this was not you, please change your password immediately and contact support.
`, deviceName, location, ip, data.Timestamp)

	msg := &Message{
		To:       []string{to},
		Subject:  "New Device Login Alert",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityHigh, // Security alerts are high priority
	}

	return s.SendAsync(ctx, msg)
}

// SendTwoFactorBackupCodesEmail sends 2FA backup codes
func (s *Service) SendTwoFactorBackupCodesEmail(ctx context.Context, to string, codes []string) error {
	data := &TwoFactorBackupCodesData{
		BackupCodes: codes,
	}

	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("2fa_backup_codes", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := fmt.Sprintf(`
Your Two-Factor Authentication Backup Codes

Please save these backup codes in a secure location. Each code can only be used once.

%s

Keep these codes safe and do not share them with anyone.
`, formatBackupCodes(codes))

	msg := &Message{
		To:       []string{to},
		Subject:  "Your 2FA Backup Codes",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityHigh, // Security-related emails are high priority
	}

	return s.SendAsync(ctx, msg)
}

// SendSuspiciousLoginEmail sends a suspicious login alert
func (s *Service) SendSuspiciousLoginEmail(ctx context.Context, to string, data *SuspiciousLoginData) error {
	if err := data.Validate(); err != nil {
		return fmt.Errorf("validate template data: %w", err)
	}

	htmlBody, err := s.renderTemplate("suspicious_login", data)
	if err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	textBody := fmt.Sprintf(`
SECURITY ALERT: Suspicious Login Detected

We detected a suspicious login attempt to your account.

Suspicion Level: %s
Reason: %s

Login Details:
- Device: %s
- Device Type: %s
- Location: %s
- IP Address: %s
- Time: %s

Was this you?

If you recognize this login, you can safely ignore this email.

If you did NOT authorize this login:
1. Change your password immediately
2. Review your recent account activity
3. Enable Two-Factor Authentication (2FA) if not already enabled
4. Contact our support team

Secure your account: %s

This is an automated security alert. We monitor login activity to protect your account from unauthorized access.

Need help? Contact us at support@paigram.com
© 2024 PaiGram. All rights reserved.
`,
		data.SuspicionLevel,
		data.SuspicionReason,
		data.DeviceName,
		data.DeviceType,
		data.Location,
		data.IP,
		data.Timestamp,
		data.SecurityURL,
	)

	msg := &Message{
		To:       []string{to},
		Subject:  "🔒 Security Alert: Suspicious Login Detected",
		TextBody: textBody,
		HTMLBody: htmlBody,
		Priority: PriorityCritical, // Suspicious login alerts are critical
	}

	return s.SendAsync(ctx, msg)
}

// formatBackupCodes formats backup codes for text display
func formatBackupCodes(codes []string) string {
	var buf bytes.Buffer
	for i, code := range codes {
		buf.WriteString(fmt.Sprintf("%d. %s\n", i+1, code))
	}
	return buf.String()
}

// renderTemplate renders an email template
func (s *Service) renderTemplate(name string, data interface{}) (string, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		EmailTemplateRenderDuration.WithLabelValues(name).Observe(duration)
	}()

	tmpl, err := s.templateManager.GetTemplate(name)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// ReloadTemplates reloads templates from files (for development)
func (s *Service) ReloadTemplates() error {
	return s.templateManager.Reload()
}

// ExportTemplates exports embedded templates to files
func (s *Service) ExportTemplates(outputDir string) error {
	return s.templateManager.ExportTemplates(outputDir)
}
