package secsubtle

import "testing"

func TestStringEqual_Basics(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "equal_nonempty", a: "abcdef", b: "abcdef", want: true},
		{name: "equal_empty", a: "", b: "", want: true},
		{name: "different_length", a: "abc", b: "abcd", want: false},
		{name: "different_content_same_length", a: "abcdef", b: "abcdeg", want: false},
		{name: "one_empty", a: "", b: "x", want: false},
		{name: "case_sensitive", a: "Foo", b: "foo", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := StringEqual(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("StringEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
