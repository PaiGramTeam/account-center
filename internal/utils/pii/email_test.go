package pii

import "testing"

func TestMaskEmail(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "typical", in: "alice@example.com", want: "a***@example.com"},
		{name: "short_local", in: "a@b.c", want: "*@b.c"},
		{name: "two_char_local", in: "ab@example.com", want: "a***@example.com"},
		{name: "no_at", in: "not-an-email", want: "not-an-email"},
		{name: "empty_local", in: "@example.com", want: "*@example.com"},
		{name: "multiple_at_uses_last", in: "weird@user@example.com", want: "w***@example.com"},
		{name: "uppercase_preserved", in: "Alice@Example.COM", want: "A***@Example.COM"},
		{name: "trailing_only_at", in: "alice@", want: "a***@"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MaskEmail(tc.in)
			if got != tc.want {
				t.Fatalf("MaskEmail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
