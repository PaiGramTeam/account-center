package email

import (
	"strings"
	"testing"

	"paigram/internal/config"
)

// TestSanitizeHeaderStripsCRLF guards the CWE-93 mitigation: any value
// flowing into a raw header line must have its CR/LF replaced so attackers
// cannot inject extra headers or smuggle SMTP commands.
func TestSanitizeHeaderStripsCRLF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Hello world", "Hello world"},
		{"crlf injection", "Subject\r\nBcc: attacker@evil.com", "Subject Bcc: attacker@evil.com"},
		{"lf injection", "line1\nline2", "line1 line2"},
		{"cr injection", "line1\rline2", "line1 line2"},
		{"null byte", "abc\x00def", "abc def"},
		{"trailing whitespace", "  spaced  ", "spaced"},
		{"unicode untouched", "你好 世界", "你好 世界"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeHeader(tc.in)
			if got != tc.want {
				t.Fatalf("sanitizeHeader(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n\x00") {
				t.Fatalf("sanitizeHeader output still contains control chars: %q", got)
			}
		})
	}
}

func TestSanitizeAddressRejectsInjection(t *testing.T) {
	good := []string{
		"user@example.com",
		"User Name <user@example.com>",
	}
	for _, s := range good {
		if _, err := sanitizeAddress(s); err != nil {
			t.Errorf("expected %q to validate, got error: %v", s, err)
		}
	}

	bad := []string{
		"",
		"not-an-email",
		"user@example.com\r\nBcc: attacker@evil.com",
		"user@example.com\nBcc: attacker@evil.com",
	}
	for _, s := range bad {
		if _, err := sanitizeAddress(s); err == nil {
			t.Errorf("expected %q to be rejected, got nil error", s)
		}
	}
}

// TestBuildMessageContainsNoInjectedHeaders ensures crafted Subject and
// recipient values cannot inject new header lines into the rendered SMTP
// payload.
func TestBuildMessageContainsNoInjectedHeaders(t *testing.T) {
	sender := &SMTPSender{
		cfg: config.EmailConfig{
			SMTPHost:  "smtp.example.com",
			SMTPPort:  587,
			FromEmail: "noreply@example.com",
			FromName:  "PaiGram",
		},
	}

	// Subject contains a CRLF injection attempt; To list contains a
	// header-style payload that would only be problematic if buildMessage
	// fails to sanitize. Send() validates To/CC/BCC, but buildMessage must
	// itself remain safe in case it is called with already-validated input
	// that nevertheless happens to contain CR/LF.
	msg := &Message{
		To:      []string{"victim@example.com"},
		Subject: "Hello\r\nBcc: attacker@evil.com",
	}

	body, err := sender.buildMessage(msg)
	if err != nil {
		t.Fatalf("buildMessage failed: %v", err)
	}

	// Header section is everything before the blank CRLF separator.
	headers := body
	if idx := strings.Index(body, "\r\n\r\n"); idx >= 0 {
		headers = body[:idx]
	}

	// The injected payload must not have created a new header line. We
	// assert this structurally: there must be exactly one header line that
	// starts with `Subject:` and exactly zero lines that start with `Bcc:`.
	var subjectLines, bccLines int
	for _, line := range strings.Split(headers, "\r\n") {
		switch {
		case strings.HasPrefix(line, "Subject:"):
			subjectLines++
		case strings.HasPrefix(strings.ToLower(line), "bcc:"):
			bccLines++
		}
	}
	if subjectLines != 1 {
		t.Fatalf("expected exactly 1 Subject header, got %d:\n%s", subjectLines, headers)
	}
	if bccLines != 0 {
		t.Fatalf("expected 0 Bcc headers (CRLF injection), got %d:\n%s", bccLines, headers)
	}
}

func TestSendRejectsInvalidRecipients(t *testing.T) {
	sender, err := NewSMTPSender(config.EmailConfig{
		SMTPHost:  "smtp.example.com",
		SMTPPort:  587,
		FromEmail: "noreply@example.com",
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}

	msg := &Message{
		To:      []string{"victim@example.com\r\nBcc: attacker@evil.com"},
		Subject: "Test",
	}
	if err := sender.Send(nil, msg); err == nil {
		t.Fatalf("expected Send to reject CRLF-injected recipient, got nil")
	}
}
