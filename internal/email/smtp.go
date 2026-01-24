package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"path/filepath"
	"strings"
	"time"

	"paigram/internal/config"
)

// SMTPSender implements email sending via SMTP
type SMTPSender struct {
	cfg     config.EmailConfig
	timeout time.Duration
}

// NewSMTPSender creates a new SMTP sender
func NewSMTPSender(cfg config.EmailConfig) (*SMTPSender, error) {
	if cfg.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if cfg.SMTPPort == 0 {
		return nil, fmt.Errorf("SMTP port is required")
	}
	if cfg.FromEmail == "" {
		return nil, fmt.Errorf("from email is required")
	}

	// Default timeout: 30 seconds
	timeout := 30 * time.Second
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}

	return &SMTPSender{
		cfg:     cfg,
		timeout: timeout,
	}, nil
}

// generateBoundary generates a random MIME boundary
func generateBoundary() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return fmt.Sprintf("boundary_%x", buf)
}

// Send sends an email via SMTP
func (s *SMTPSender) Send(ctx context.Context, msg *Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build email message
	body, err := s.buildMessage(msg)
	if err != nil {
		return fmt.Errorf("build message: %w", err)
	}

	// All recipients
	recipients := make([]string, 0, len(msg.To)+len(msg.CC)+len(msg.BCC))
	recipients = append(recipients, msg.To...)
	recipients = append(recipients, msg.CC...)
	recipients = append(recipients, msg.BCC...)

	// Send email with timeout
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)

	// Create context with timeout
	sendCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if s.cfg.UseTLS {
		return s.sendWithTLS(sendCtx, addr, recipients, body)
	}

	return s.sendPlain(sendCtx, addr, recipients, body)
}

// buildMessage constructs the email message with proper MIME encoding
func (s *SMTPSender) buildMessage(msg *Message) (string, error) {
	var builder strings.Builder

	// Headers
	builder.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.cfg.FromName, s.cfg.FromEmail))
	builder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	if len(msg.CC) > 0 {
		builder.WriteString(fmt.Sprintf("CC: %s\r\n", strings.Join(msg.CC, ", ")))
	}

	builder.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
	builder.WriteString("MIME-Version: 1.0\r\n")

	// Determine if we need multipart
	hasAttachments := len(msg.Attachments) > 0
	hasHTML := msg.HTMLBody != ""

	if hasAttachments {
		// Use multipart/mixed for attachments
		mixedBoundary := generateBoundary()
		builder.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", mixedBoundary))

		// Body part (could be multipart/alternative itself)
		builder.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))

		if hasHTML {
			altBoundary := generateBoundary()
			builder.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", altBoundary))

			// Text part
			builder.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			builder.WriteString(msg.TextBody)
			builder.WriteString("\r\n")

			// HTML part
			builder.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			builder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
			builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			builder.WriteString(msg.HTMLBody)
			builder.WriteString("\r\n")

			builder.WriteString(fmt.Sprintf("--%s--\r\n\r\n", altBoundary))
		} else {
			builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			builder.WriteString(msg.TextBody)
			builder.WriteString("\r\n\r\n")
		}

		// Attachments
		for _, att := range msg.Attachments {
			builder.WriteString(fmt.Sprintf("--%s\r\n", mixedBoundary))

			// Determine MIME type
			mimeType := att.MimeType
			if mimeType == "" {
				mimeType = mime.TypeByExtension(filepath.Ext(att.Filename))
				if mimeType == "" {
					mimeType = "application/octet-stream"
				}
			}

			builder.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", mimeType, att.Filename))
			builder.WriteString("Content-Transfer-Encoding: base64\r\n")
			builder.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", att.Filename))

			// Encode attachment in base64
			encoded := base64.StdEncoding.EncodeToString(att.Content)
			// Split into 76-character lines as per RFC 2045
			for i := 0; i < len(encoded); i += 76 {
				end := i + 76
				if end > len(encoded) {
					end = len(encoded)
				}
				builder.WriteString(encoded[i:end])
				builder.WriteString("\r\n")
			}
		}

		builder.WriteString(fmt.Sprintf("--%s--\r\n", mixedBoundary))
	} else if hasHTML {
		// Use multipart/alternative for HTML + text
		boundary := generateBoundary()
		builder.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

		// Text part
		builder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		builder.WriteString(msg.TextBody)
		builder.WriteString("\r\n")

		// HTML part
		builder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		builder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		builder.WriteString(msg.HTMLBody)
		builder.WriteString("\r\n")

		builder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple text email
		builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		builder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		builder.WriteString(msg.TextBody)
	}

	return builder.String(), nil
}

// sendWithTLS sends email using TLS with timeout support
func (s *SMTPSender) sendWithTLS(ctx context.Context, addr string, recipients []string, body string) error {
	// TLS config with security improvements
	tlsConfig := &tls.Config{
		ServerName:         s.cfg.SMTPHost,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}

	// Connect with timeout
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Set deadline for the entire operation
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Quit()

	// Auth
	if s.cfg.SMTPUsername != "" && s.cfg.SMTPPassword != "" {
		auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(s.cfg.FromEmail); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("set recipient %s: %w", recipient, err)
		}
	}

	// Send body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("create data writer: %w", err)
	}

	_, err = w.Write([]byte(body))
	if err != nil {
		return fmt.Errorf("write email body: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}

	return nil
}

// sendPlain sends email using STARTTLS with timeout support
func (s *SMTPSender) sendPlain(ctx context.Context, addr string, recipients []string, body string) error {
	// Connect with timeout
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Quit()

	// Try STARTTLS if available
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: s.cfg.SMTPHost,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	// Auth
	if s.cfg.SMTPUsername != "" && s.cfg.SMTPPassword != "" {
		auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(s.cfg.FromEmail); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("set recipient %s: %w", recipient, err)
		}
	}

	// Send body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("create data writer: %w", err)
	}

	_, err = w.Write([]byte(body))
	if err != nil {
		return fmt.Errorf("write email body: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("close data writer: %w", err)
	}

	return nil
}

// NoopSender is a no-op implementation for when email is disabled
type NoopSender struct{}

// Send does nothing
func (n *NoopSender) Send(ctx context.Context, msg *Message) error {
	return nil
}
