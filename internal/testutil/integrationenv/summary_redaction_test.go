package integrationenv

import (
	"strings"
	"testing"
)

// TestSummaryLinesNeverLeaksPasswords guards the CWE-312 (clear-text logging)
// mitigation: SummaryLines must never embed the raw value of MySQLPassword
// or RedisPassword in its output, regardless of how exotic the configured
// secrets look.
func TestSummaryLinesNeverLeaksPasswords(t *testing.T) {
	mysqlSecret := "super-secret-mysql-pa55w0rd-NEVER-LEAK"
	redisSecret := "another-secret-redis-pa55w0rd-NEVER-LEAK"

	env := Env{
		RepoRoot:      "/tmp/repo",
		EnvFilePath:   "/tmp/repo/.env.integration.local",
		EnvFileLoaded: true,
		GoWork:        "off",
		MySQLAddr:     "127.0.0.1:3306",
		MySQLUsername: "root",
		MySQLPassword: mysqlSecret,
		MySQLDatabase: "paigram_test",
		MySQLConfig:   "charset=utf8mb4",
		RedisAddr:     "127.0.0.1:6379",
		RedisPassword: redisSecret,
		RedisDB:       0,
		RedisPrefix:   "itest",
	}

	for _, line := range env.SummaryLines("doctor", true) {
		if strings.Contains(line, mysqlSecret) {
			t.Errorf("SummaryLines leaked MySQLPassword in line: %q", line)
		}
		if strings.Contains(line, redisSecret) {
			t.Errorf("SummaryLines leaked RedisPassword in line: %q", line)
		}
	}
}

// TestRedactedPasswordTagReturnsLiterals asserts the helper only ever
// returns one of two literal constants, which is what allows static
// analysers to terminate taint flow.
func TestRedactedPasswordTagReturnsLiterals(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "<empty>"},
		{"   ", "<empty>"},
		{"\t\n", "<empty>"},
		{"actual-password", "<redacted>"},
		{"another-leaky-secret", "<redacted>"},
	}
	for _, tc := range cases {
		got := redactedPasswordTag(tc.in)
		if got != tc.want {
			t.Errorf("redactedPasswordTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
