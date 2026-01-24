package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"paigram/internal/config"
)

// SMTPSender implements email sending via SMTP
type SMTPSender struct {
	cfg config.EmailConfig
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

	return &SMTPSender{cfg: cfg}, nil
}

// Send sends an email via SMTP
func (s *SMTPSender) Send(ctx context.Context, msg *Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build email message
	var emailBody strings.Builder
	emailBody.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.cfg.FromName, s.cfg.FromEmail))
	emailBody.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	if len(msg.CC) > 0 {
		emailBody.WriteString(fmt.Sprintf("CC: %s\r\n", strings.Join(msg.CC, ", ")))
	}

	emailBody.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))
	emailBody.WriteString("MIME-Version: 1.0\r\n")

	// If we have HTML body, use multipart
	if msg.HTMLBody != "" {
		boundary := "boundary123456789"
		emailBody.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

		// Text part
		emailBody.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		emailBody.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		emailBody.WriteString(msg.TextBody)
		emailBody.WriteString("\r\n\r\n")

		// HTML part
		emailBody.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		emailBody.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		emailBody.WriteString(msg.HTMLBody)
		emailBody.WriteString("\r\n\r\n")

		emailBody.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		emailBody.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		emailBody.WriteString(msg.TextBody)
	}

	// All recipients
	recipients := make([]string, 0, len(msg.To)+len(msg.CC)+len(msg.BCC))
	recipients = append(recipients, msg.To...)
	recipients = append(recipients, msg.CC...)
	recipients = append(recipients, msg.BCC...)

	// Send email
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)

	if s.cfg.UseTLS {
		return s.sendWithTLS(addr, recipients, emailBody.String())
	}

	return s.sendPlain(addr, recipients, emailBody.String())
}

// sendWithTLS sends email using TLS
func (s *SMTPSender) sendWithTLS(addr string, recipients []string, body string) error {
	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)

	// TLS config
	tlsConfig := &tls.Config{
		ServerName: s.cfg.SMTPHost,
	}

	// Connect to SMTP server
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Quit()

	// Auth
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP auth: %w", err)
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

// sendPlain sends email without TLS
func (s *SMTPSender) sendPlain(addr string, recipients []string, body string) error {
	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	return smtp.SendMail(addr, auth, s.cfg.FromEmail, recipients, []byte(body))
}

// NoopSender is a no-op implementation for when email is disabled
type NoopSender struct{}

// Send does nothing
func (n *NoopSender) Send(ctx context.Context, msg *Message) error {
	return nil
}
