package middleware

import (
	"os"
	"strings"
	"testing"
)

// TestPermissionMiddleware_NoHeaderQueryFallback is a static-scan test that
// asserts the permission middleware does NOT contain X-User-ID header or
// user_id query string fallbacks for resolving the authenticated user.
//
// Background (V20): The previous implementation had a fallback path that
// trusted X-User-ID / user_id from the request, which would let any caller
// impersonate any user if the function were ever invoked from authenticated
// code. The function is currently uncalled, but the dead-code path must be
// removed so a future engineer cannot accidentally re-enable the bypass.
func TestPermissionMiddleware_NoHeaderQueryFallback(t *testing.T) {
	const path = "permission.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)

	forbidden := []string{
		`c.GetHeader("X-User-ID")`,
		`c.Query("user_id")`,
	}
	for _, needle := range forbidden {
		if strings.Contains(src, needle) {
			t.Errorf("%s must not contain %q (V20: client-supplied user ID bypass)", path, needle)
		}
	}
}
