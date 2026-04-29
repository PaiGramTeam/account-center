package safeerror_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRawErrErrorInResponses is a regression-prevention "lint" mirroring
// secsubtle's TestNoRawTokenEqualityComparisons (V18/C3) and pii's coverage
// (C2). It scans every handler file C7/V13 swept and asserts that none of the
// pre-fix patterns has crept back in:
//
//  1. response.<X>(c, err.Error())  — direct echo of internal error text.
//  2. response.<X>(c, "...prefix: " + err.Error(), ...) — concatenated leak.
//  3. response.<X>WithCode(c, code, err.Error(), nil) — leak via WithCode form.
//
// Because the fix-up rule is "never pipe err.Error() into a response body",
// the expected match count is zero across the listed files.
//
// Notes:
//   - `strings.Contains(err.Error(), "...")` for INTERNAL routing logic is
//     allowed; the regex matches only `response.\w+(c, ...err.Error()` shapes.
//   - Comments in source that mention `err.Error()` are not matched: they do
//     not start with `response.<word>(c, `.
//   - password_reset.go is intentionally excluded — its remaining
//     `gin.H{"error": err.Error()}` sites belong to a different commit's
//     scope and are tracked separately.
func TestNoRawErrErrorInResponses(t *testing.T) {
	root := repoRoot(t)

	// V13 paths from the C7 audit (9 handler files).
	swept := []string{
		filepath.Join("internal", "handler", "user", "user_handler.go"),
		filepath.Join("internal", "handler", "user", "login_method_handler.go"),
		filepath.Join("internal", "handler", "me", "current_user_handler.go"),
		filepath.Join("internal", "handler", "me", "security_handler.go"),
		filepath.Join("internal", "handler", "me", "session_handler.go"),
		filepath.Join("internal", "handler", "authority", "authority_handler.go"),
		filepath.Join("internal", "handler", "casbin", "casbin_handler.go"),
		filepath.Join("internal", "handler", "auth", "email.go"),
		filepath.Join("internal", "handler", "auth", "oauth.go"),
	}

	// Match: response.<word>(c, ANY-non-comma-junk err.Error()
	// `[^,]*` ensures we stay within the second positional argument so
	// `strings.Contains(err.Error(), "...")` inside the body does not match.
	rawErrInResponse := regexp.MustCompile(`response\.\w+\(c,\s*[^,)]*err\.Error\(\)`)

	// Match: response.<word>WithCode(c, <code>, ANY-non-comma-junk err.Error()
	// (the user-message slot is the THIRD positional arg in *WithCode.)
	rawErrInResponseWithCode := regexp.MustCompile(`response\.\w+WithCode\(c,\s*[^,]+,\s*[^,)]*err\.Error\(\)`)

	for _, rel := range swept {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			full := filepath.Join(root, rel)
			data, err := os.ReadFile(full)
			if err != nil {
				t.Fatalf("read %s: %v", full, err)
			}
			src := string(data)

			if loc := rawErrInResponse.FindStringIndex(src); loc != nil {
				t.Errorf("V13 regression in %s: raw err.Error() interpolated into a response body\n  matched: %q",
					rel, snippet(src, loc))
			}
			if loc := rawErrInResponseWithCode.FindStringIndex(src); loc != nil {
				t.Errorf("V13 regression in %s: raw err.Error() interpolated into a *WithCode response\n  matched: %q",
					rel, snippet(src, loc))
			}

			// Also forbid the "prefix: " + err.Error() shape: this was the
			// concat form C7 stripped (and is not always covered by the
			// regexes above when the format differs).
			if strings.Contains(src, `: "+err.Error()`) || strings.Contains(src, `: " + err.Error()`) {
				t.Errorf("V13 regression in %s: \"...: \" + err.Error() concat shape still present", rel)
			}
		})
	}
}

// snippet returns up to 120 chars around the match for helpful diagnostics.
func snippet(src string, loc []int) string {
	start := loc[0]
	end := loc[1]
	if end-start < 80 {
		end = start + 120
		if end > len(src) {
			end = len(src)
		}
	}
	return src[start:end]
}

// repoRoot walks upward from this test file until it finds go.mod and returns
// the directory containing it. Mirrors secsubtle's helper so this lint stays
// robust against the working directory go test is invoked from.
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
