package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAdminPathsUseBcryptDefaultCost is a static-scan style assertion
// guarding the V8 fix: the admin/seed/user-handler password-hashing
// paths must consult the operator-configured bcrypt cost rather than
// bcrypt.DefaultCost (which is 10 — below the OWASP minimum of 12).
//
// Test files are deliberately not scanned: tests legitimately use the
// cheap default cost to keep suite times reasonable.
//
// Scope note: V8 was bounded to 5 specific production sites (see C4
// task spec). The lint covers exactly those sites. See
// knownExcludedFromV8 below for two adjacent sites that hash passwords
// via hard-coded constants rather than bcrypt.DefaultCost — they are
// not yet operator-configurable but also not regressions of V8. Track
// in the security follow-up backlog.
func TestNoAdminPathsUseBcryptDefaultCost(t *testing.T) {
	root := repoRootForLint(t)

	productionPaths := []string{
		filepath.Join(root, "initialize", "seed", "admin.go"),
		filepath.Join(root, "cmd", "paigram", "cmd", "admin.go"),
		filepath.Join(root, "internal", "handler", "user", "user_handler.go"),
	}

	for _, path := range productionPaths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), "bcrypt.DefaultCost") {
			t.Errorf("V8 regression: %s still references bcrypt.DefaultCost; use the operator-configured cost instead", path)
		}
	}
}

// TestKnownExcludedFromV8AreStillExcluded is a tripwire: the files in
// knownExcludedFromV8 are documented-but-not-yet-fixed bcrypt cost
// sources. If any of them ever gains a `bcrypt.DefaultCost` reference,
// fail loudly so we don't silently inherit the V8 bug. Conversely, if
// any of them is migrated to read from the operator config, this test
// will keep passing — the next maintainer should then remove the entry
// from knownExcludedFromV8 and add the file to TestNoAdminPathsUseBcryptDefaultCost.
func TestKnownExcludedFromV8AreStillExcluded(t *testing.T) {
	root := repoRootForLint(t)

	for _, entry := range knownExcludedFromV8 {
		path := filepath.Join(root, filepath.FromSlash(entry.path))
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), "bcrypt.DefaultCost") {
			t.Errorf("V8 regression in known-excluded file %s (%s); fix it AND remove the exclusion entry", path, entry.rationale)
		}
	}
}

// knownExcludedFromV8 lists production password-hashing paths that the
// V8 task spec deliberately did NOT cover. They use a hard-coded local
// constant set to the OWASP-recommended 12, which is functionally safe
// today but is NOT wired to security.bcrypt_cost — so an operator who
// raises the configured cost will not see it applied here. Each entry
// should be migrated to read cfg.GetBcryptCost() in a follow-up commit.
//
// TODO(security): refactor each entry to consume the configured cost
// (mirroring the V8 fix in user_handler.go). When done, delete the
// entry below and add the file to TestNoAdminPathsUseBcryptDefaultCost
// so the stronger lint applies.
var knownExcludedFromV8 = []struct {
	path      string // path relative to repo root, slash-separated
	rationale string
}{
	{
		path:      "internal/service/me/security_service.go",
		rationale: "uses const defaultBcryptCost = 12 for /me/change-password and 2FA backup-code hashing; not yet wired to security.bcrypt_cost",
	},
	{
		path:      "internal/grpc/service/bot_auth_service.go",
		rationale: "uses const BcryptCost = 12 for hashing bot API secrets; not yet wired to security.bcrypt_cost",
	},
}

// repoRootForLint walks up from the package directory until it finds
// go.mod, returning that directory. Used by both lint-style tests in
// this file.
func repoRootForLint(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		root = filepath.Dir(root)
	}
	t.Fatalf("could not locate go.mod walking up from %s", wd)
	return ""
}
