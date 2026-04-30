package user

import "testing"

// TestResolveListUsersOrderClause guards the CWE-89 mitigation: every (sort,
// order) pair must resolve to a constant SQL fragment that can never carry
// attacker-controlled bytes into the ORDER BY clause.
func TestResolveListUsersOrderClause(t *testing.T) {
	cases := []struct {
		name     string
		sortBy   string
		order    string
		expected string
	}{
		{"empty defaults to created_at desc", "", "", "created_at DESC"},
		{"id asc", "id", "asc", "id ASC"},
		{"id desc", "id", "desc", "id DESC"},
		{"created_at asc", "created_at", "asc", "created_at ASC"},
		{"created_at desc", "created_at", "desc", "created_at DESC"},
		{"last_login_at asc", "last_login_at", "asc", "last_login_at ASC"},
		{"last_login_at desc", "last_login_at", "desc", "last_login_at DESC"},
		{"order is case-insensitive", "id", "ASC", "id ASC"},
		{"unknown sort field falls back", "DROP TABLE users; --", "asc", "created_at DESC"},
		{"unknown order falls back to desc", "id", "boom", "id DESC"},
		{"injection in sort field", "id; DROP TABLE users", "asc", "created_at DESC"},
		{"injection in order falls back to desc", "id", "asc; DROP TABLE users", "id DESC"},
		{"whitespace in sort field is trimmed", " id ", "asc", "id ASC"},
		{"whitespace in order is trimmed", "id", "  asc  ", "id ASC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveListUsersOrderClause(tc.sortBy, tc.order)
			if got != tc.expected {
				t.Fatalf("resolveListUsersOrderClause(%q, %q) = %q, want %q",
					tc.sortBy, tc.order, got, tc.expected)
			}
		})
	}
}

// TestResolveListUsersOrderClauseValuesAreConstants asserts that every value
// in the allow-list is one of the expected constants. This makes regressions
// (e.g. someone interpolating user input into a value) immediately visible.
func TestResolveListUsersOrderClauseValuesAreConstants(t *testing.T) {
	expected := map[string]struct{}{
		"id ASC":             {},
		"id DESC":            {},
		"created_at ASC":     {},
		"created_at DESC":    {},
		"last_login_at ASC":  {},
		"last_login_at DESC": {},
	}
	for key, value := range allowedListUsersOrderClauses {
		if _, ok := expected[value]; !ok {
			t.Errorf("allowedListUsersOrderClauses[%q] = %q is not in the expected constant set", key, value)
		}
	}
}

// TestResolveListUsersOrderClauseAlwaysReturnsAllowedConstant fuzzes the
// resolver with hostile inputs and asserts that the output is always exactly
// one of the constants from the allow-list — i.e. user bytes can never reach
// the rendered SQL fragment.
func TestResolveListUsersOrderClauseAlwaysReturnsAllowedConstant(t *testing.T) {
	allowed := map[string]struct{}{
		"id ASC":             {},
		"id DESC":            {},
		"created_at ASC":     {},
		"created_at DESC":    {},
		"last_login_at ASC":  {},
		"last_login_at DESC": {},
	}

	hostileSortFields := []string{
		"",
		"id",
		"created_at",
		"last_login_at",
		"unknown_field",
		"id; DROP TABLE users",
		"id--",
		"id /*comment*/",
		"id\nUNION SELECT password FROM users",
		"`id`",
		"\"id\"",
		"id') OR ('1'='1",
		"日本語",
	}
	hostileOrders := []string{
		"",
		"asc",
		"desc",
		"ASC",
		"DESC",
		"asc; DROP TABLE users",
		"desc--",
		"asc UNION SELECT 1",
		"%",
		"\\",
		"日本語",
	}

	for _, sortBy := range hostileSortFields {
		for _, order := range hostileOrders {
			got := resolveListUsersOrderClause(sortBy, order)
			if _, ok := allowed[got]; !ok {
				t.Errorf("resolveListUsersOrderClause(%q, %q) returned non-allowlisted clause %q",
					sortBy, order, got)
			}
		}
	}
}
