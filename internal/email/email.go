package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"time"

	"go.uber.org/zap"

	"paigram/internal/config"
	"paigram/internal/logging"
)

// Service handles email sending functionality
type Service struct {
	cfg    config.EmailConfig
	sender Sender
	queue  Queue
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
}

// Attachment represents an email attachment
type Attachment struct {
	Filename string
	Content  []byte
	MimeType string
}

// NewService creates a new email service
func NewService(cfg config.EmailConfig) (*Service, error) {
	if !cfg.Enabled {
		return &Service{
			cfg:    cfg,
			sender: &NoopSender{},
			queue:  &NoopQueue{},
		}, nil
	}

	var sender Sender
	var err error

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
		queue = NewMemoryQueue(sender, cfg)
	} else {
		queue = &NoopQueue{}
	}

	return &Service{
		cfg:    cfg,
		sender: sender,
		queue:  queue,
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

	return s.sender.Send(ctx, msg)
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

// SendVerificationEmail sends an email verification email
func (s *Service) SendVerificationEmail(ctx context.Context, to, token, baseURL string) error {
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", baseURL, token)

	htmlBody, err := renderTemplate("email_verification", map[string]interface{}{
		"VerifyURL": verifyURL,
		"Token":     token,
	})
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
	}

	return s.SendAsync(ctx, msg)
}

// SendPasswordResetEmail sends a password reset email
func (s *Service) SendPasswordResetEmail(ctx context.Context, to, token, baseURL string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)

	htmlBody, err := renderTemplate("password_reset", map[string]interface{}{
		"ResetURL": resetURL,
	})
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
	}

	return s.SendAsync(ctx, msg)
}

// SendPasswordChangedEmail sends a notification when password is changed
func (s *Service) SendPasswordChangedEmail(ctx context.Context, to string) error {
	htmlBody, err := renderTemplate("password_changed", map[string]interface{}{
		"Timestamp": time.Now().Format("2006-01-02 15:04:05 MST"),
	})
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
	}

	return s.SendAsync(ctx, msg)
}

// SendNewDeviceLoginEmail sends a notification for new device login
func (s *Service) SendNewDeviceLoginEmail(ctx context.Context, to, deviceName, location, ip string) error {
	htmlBody, err := renderTemplate("new_device_login", map[string]interface{}{
		"DeviceName": deviceName,
		"Location":   location,
		"IP":         ip,
		"Timestamp":  time.Now().Format("2006-01-02 15:04:05 MST"),
	})
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
`, deviceName, location, ip, time.Now().Format("2006-01-02 15:04:05 MST"))

	msg := &Message{
		To:       []string{to},
		Subject:  "New Device Login Alert",
		TextBody: textBody,
		HTMLBody: htmlBody,
	}

	return s.SendAsync(ctx, msg)
}

// SendTwoFactorBackupCodesEmail sends 2FA backup codes
func (s *Service) SendTwoFactorBackupCodesEmail(ctx context.Context, to string, codes []string) error {
	htmlBody, err := renderTemplate("2fa_backup_codes", map[string]interface{}{
		"BackupCodes": codes,
	})
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
func renderTemplate(name string, data interface{}) (string, error) {
	tmpl, ok := templates[name]
	if !ok {
		return "", fmt.Errorf("template not found: %s", name)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// templates holds pre-compiled email templates
var templates = map[string]*template.Template{
	"email_verification": template.Must(template.New("email_verification").Parse(emailVerificationTemplate)),
	"password_reset":     template.Must(template.New("password_reset").Parse(passwordResetTemplate)),
	"password_changed":   template.Must(template.New("password_changed").Parse(passwordChangedTemplate)),
	"new_device_login":   template.Must(template.New("new_device_login").Parse(newDeviceLoginTemplate)),
	"2fa_backup_codes":   template.Must(template.New("2fa_backup_codes").Parse(twoFactorBackupCodesTemplate)),
}
