package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"path/filepath"
	"strings"
	"time"

	"paigram/internal/config"
)

// sanitizeHeader strips CR/LF and other control characters that would allow
// SMTP/email header injection (CWE-93). It is applied to every value that
// flows into a raw header string built via fmt.Sprintf in buildMessage.
func sanitizeHeader(value string) string {
	// Replace CR, LF and NUL with a single space so structurally invalid
	// characters cannot terminate a header line or inject new headers.
	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ")
	cleaned := replacer.Replace(value)
	// Collapse runs of whitespace introduced by sanitization.
	return strings.TrimSpace(strings.Join(strings.Fields(cleaned), " "))
}

// sanitizeAddress validates and normalizes an email address before it is used
// either as an SMTP envelope address (MAIL FROM / RCPT TO) or interpolated
// into header values. Invalid addresses are rejected to prevent injection of
// SMTP commands or extra recipients via crafted strings.
func sanitizeAddress(address string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("invalid email address %q: %w", address, err)
	}
	// mail.Address.Address never contains CR/LF, but defend in depth.
	clean := sanitizeHeader(addr.Address)
	if clean == "" || !strings.Contains(clean, "@") {
		return "", fmt.Errorf("invalid email address %q", address)
	}
	return clean, nil
}

// sanitizeAddresses validates a slice of recipient addresses and returns the
// cleaned list, or an error if any entry is invalid.
func sanitizeAddresses(addresses []string) ([]string, error) {
	out := make([]string, 0, len(addresses))
	for _, raw := range addresses {
		clean, err := sanitizeAddress(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, clean)
	}
	return out, nil
}

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

	// Validate and sanitize all envelope addresses before they reach the
	// SMTP transaction or get interpolated into raw header bytes. This is
	// the primary mitigation for CWE-93 (email/SMTP header injection).
	cleanTo, err := sanitizeAddresses(msg.To)
	if err != nil {
		return fmt.Errorf("validate To: %w", err)
	}
	cleanCC, err := sanitizeAddresses(msg.CC)
	if err != nil {
		return fmt.Errorf("validate CC: %w", err)
	}
	cleanBCC, err := sanitizeAddresses(msg.BCC)
	if err != nil {
		return fmt.Errorf("validate BCC: %w", err)
	}
	sanitized := *msg
	sanitized.To = cleanTo
	sanitized.CC = cleanCC
	sanitized.BCC = cleanBCC

	// Build email message
	body, err := s.buildMessage(&sanitized)
	if err != nil {
		return fmt.Errorf("build message: %w", err)
	}

	// All recipients
	recipients := make([]string, 0, len(cleanTo)+len(cleanCC)+len(cleanBCC))
	recipients = append(recipients, cleanTo...)
	recipients = append(recipients, cleanCC...)
	recipients = append(recipients, cleanBCC...)

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

// buildMessage constructs the email message with proper MIME encoding.
// All values that flow into raw header lines are passed through
// sanitizeHeader to strip CR/LF and prevent header injection.
func (s *SMTPSender) buildMessage(msg *Message) (string, error) {
	var builder strings.Builder

	// Headers — every interpolated value is sanitized to ensure no CR/LF
	// can break out of its header line.
	fromName := sanitizeHeader(s.cfg.FromName)
	fromEmail := sanitizeHeader(s.cfg.FromEmail)
	builder.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, fromEmail))
	builder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	if len(msg.CC) > 0 {
		builder.WriteString(fmt.Sprintf("CC: %s\r\n", strings.Join(msg.CC, ", ")))
	}

	// RFC 2047 encode the subject so user-supplied content cannot inject
	// headers and non-ASCII characters survive. mime.QEncoding rejects
	// CR/LF inside the encoded-word, so this also defends against
	// injection if sanitizeHeader were ever bypassed.
	builder.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", sanitizeHeader(msg.Subject))))
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

			// Sanitize filename and MIME type — both flow into raw
			// header values and must not contain CR/LF or quotes that
			// could break out of the quoted-string.
			safeFilename := sanitizeHeader(strings.ReplaceAll(att.Filename, "\"", ""))
			safeMime := sanitizeHeader(mimeType)
			builder.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", safeMime, safeFilename))
			builder.WriteString("Content-Transfer-Encoding: base64\r\n")
			builder.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", safeFilename))

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

	// The MAIL FROM address is administrator-controlled config but we still
	// validate it once per send so a misconfigured value cannot inject SMTP
	// commands at the protocol level.
	fromEmail, err := sanitizeAddress(s.cfg.FromEmail)
	if err != nil {
		return fmt.Errorf("invalid from email: %w", err)
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
	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}

	// Set recipients (already sanitized by Send before this is reached)
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
	// Validate from address before opening the connection so a bad config
	// surfaces as an immediate error.
	fromEmail, err := sanitizeAddress(s.cfg.FromEmail)
	if err != nil {
		return fmt.Errorf("invalid from email: %w", err)
	}

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
	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("set sender: %w", err)
	}

	// Set recipients (already sanitized by Send before this is reached)
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
