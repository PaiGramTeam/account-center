package cmd

import (
	"strings"
	"testing"
)

// TestValidateNewPassword codifies the V9 password-policy fix: the CLI
// must enforce the same 8-72 character bound that the HTTP layer uses.
// Previously the CLI accepted 6+ characters, contradicting the rest of
// the system.
func TestValidateNewPassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
		errSub   string
	}{
		{name: "empty", password: "", wantErr: true, errSub: "8"},
		{name: "7 chars rejected", password: "1234567", wantErr: true, errSub: "8"},
		{name: "8 chars accepted", password: "12345678", wantErr: false},
		{name: "12 chars accepted", password: "Password123!", wantErr: false},
		{name: "72 chars accepted", password: strings.Repeat("a", 72), wantErr: false},
		{name: "73 chars rejected", password: strings.Repeat("a", 73), wantErr: true, errSub: "72"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNewPassword(tc.password)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.password)
				}
				if tc.errSub != "" && !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("expected error to mention %q, got %q", tc.errSub, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error for %q, got %v", tc.password, err)
			}
		})
	}
}
