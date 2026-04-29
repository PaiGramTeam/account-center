package secsubtle_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawTokenEqualityComparisons is a regression-prevention "lint": it
// scans the specific source files where V18/C3 swapped Go's built-in `==`/
// `!=` operator for secsubtle.StringEqual on sensitive token-hash equality
// checks, and asserts the old patterns have not crept back in.
//
// secsubtle.StringEqual itself is unit-tested in this package (subtle_test.go);
// here we only enforce that the documented call sites use it.
//
// To find the repo root we walk up from this test file's directory until we
// see go.mod. That keeps the test independent of the working directory
// `go test` is invoked from.
func TestNoRawTokenEqualityComparisons(t *testing.T) {
	root := repoRoot(t)

	type rule struct {
		// Path is relative to the repo root.
		Path string
		// Forbidden is a regexp the file must NOT match. Each is a known
		// pre-fix pattern from V18.
		Forbidden *regexp.Regexp
		// MustImportSecsubtle, when true, also asserts the file references
		// secsubtle (either as an import or as a `secsubtle.StringEqual` call,
		// since fileset entries with multiple sites collapse on the same import).
		MustImportSecsubtle bool
	}

	rules := []rule{
		{
			Path:                filepath.Join("internal", "middleware", "auth.go"),
			Forbidden:           regexp.MustCompile(`string\(currentAccessHash\)\s*!=\s*accessTokenHash`),
			MustImportSecsubtle: true,
		},
		{
			Path:                filepath.Join("internal", "handler", "auth", "email.go"),
			Forbidden:           regexp.MustCompile(`session\.RefreshTokenHash\s*!=\s*refreshTokenHash`),
			MustImportSecsubtle: true,
		},
		{
			// Same file, second site (V12 folded into V18).
			Path:                filepath.Join("internal", "handler", "auth", "email.go"),
			Forbidden:           regexp.MustCompile(`hashToken\(req\.Token\)\s*!=\s*emailRecord\.VerificationToken`),
			MustImportSecsubtle: true,
		},
		{
			Path:                filepath.Join("internal", "service", "me", "session_service.go"),
			Forbidden:           regexp.MustCompile(`session\.AccessTokenHash\s*==\s*currentTokenHash`),
			MustImportSecsubtle: true,
		},
		{
			Path:                filepath.Join("internal", "handler", "user", "user_handler.go"),
			Forbidden:           regexp.MustCompile(`session\.AccessTokenHash\s*==\s*currentTokenHash`),
			MustImportSecsubtle: true,
		},
	}

	for _, r := range rules {
		r := r
		t.Run(r.Path+"/"+r.Forbidden.String(), func(t *testing.T) {
			full := filepath.Join(root, r.Path)
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatalf("read %s: %v", full, err)
			}
			src := string(data)

			if loc := r.Forbidden.FindStringIndex(src); loc != nil {
				t.Errorf("V18 regression: forbidden pattern %s still present in %s\n  matched fragment: %q",
					r.Forbidden.String(), r.Path, src[loc[0]:loc[1]])
			}

			if r.MustImportSecsubtle && !strings.Contains(src, "secsubtle") {
				t.Errorf("V18: %s no longer references secsubtle (constant-time helper)", r.Path)
			}
		})
	}
}

// repoRoot walks upward from this test file until it finds go.mod and returns
// the directory containing it.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod walking up from %s", wd)
	return ""
}
