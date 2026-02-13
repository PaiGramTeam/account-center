package middleware

import (
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name           string
		ip             string
		ipv6SubnetBits int
		expected       string
		description    string
	}{
		// IPv4 tests
		{
			name:           "IPv4 standard",
			ip:             "192.0.2.1",
			ipv6SubnetBits: 64,
			expected:       "192.0.2.1",
			description:    "IPv4 should remain unchanged",
		},
		{
			name:           "IPv4 localhost",
			ip:             "127.0.0.1",
			ipv6SubnetBits: 64,
			expected:       "127.0.0.1",
			description:    "IPv4 localhost should remain unchanged",
		},

		// IPv4-mapped IPv6 tests
		{
			name:           "IPv4-mapped IPv6 to IPv4",
			ip:             "::ffff:192.0.2.1",
			ipv6SubnetBits: 64,
			expected:       "192.0.2.1",
			description:    "IPv4-mapped IPv6 should convert to IPv4",
		},
		{
			name:           "IPv4-mapped IPv6 localhost",
			ip:             "::ffff:127.0.0.1",
			ipv6SubnetBits: 64,
			expected:       "127.0.0.1",
			description:    "IPv4-mapped IPv6 localhost should convert",
		},

		// IPv6 normalization tests
		{
			name:           "IPv6 full form",
			ip:             "2001:0db8:0000:0000:0000:0000:0000:0001",
			ipv6SubnetBits: 128,
			expected:       "2001:db8::1",
			description:    "IPv6 should normalize to compressed form when /128",
		},
		{
			name:           "IPv6 compressed",
			ip:             "2001:db8::1",
			ipv6SubnetBits: 128,
			expected:       "2001:db8::1",
			description:    "Compressed IPv6 should remain the same when /128",
		},

		// IPv6 subnet masking tests (prevent rotation bypass)
		{
			name:           "IPv6 /64 subnet masking",
			ip:             "2001:db8:1234:5678:abcd:ef01:2345:6789",
			ipv6SubnetBits: 64,
			expected:       "2001:db8:1234:5678::",
			description:    "/64 should mask host portion",
		},
		{
			name:           "IPv6 /64 different host same subnet",
			ip:             "2001:db8:1234:5678:1111:2222:3333:4444",
			ipv6SubnetBits: 64,
			expected:       "2001:db8:1234:5678::",
			description:    "Different hosts in same /64 should map to same key",
		},
		{
			name:           "IPv6 /48 subnet masking",
			ip:             "2001:db8:1234:5678:abcd:ef01:2345:6789",
			ipv6SubnetBits: 48,
			expected:       "2001:db8:1234::",
			description:    "/48 should mask more bits",
		},
		{
			name:           "IPv6 /32 subnet masking",
			ip:             "2001:db8:1234:5678:abcd:ef01:2345:6789",
			ipv6SubnetBits: 32,
			expected:       "2001:db8::",
			description:    "/32 ISP-level allocation",
		},

		// Edge cases
		{
			name:           "IPv6 loopback",
			ip:             "::1",
			ipv6SubnetBits: 128,
			expected:       "::1",
			description:    "IPv6 loopback should remain unchanged",
		},
		{
			name:           "IPv6 any address",
			ip:             "::",
			ipv6SubnetBits: 64,
			expected:       "::",
			description:    "IPv6 any address should remain unchanged",
		},
		{
			name:           "Invalid subnet bits (too high)",
			ip:             "2001:db8::1",
			ipv6SubnetBits: 256,
			expected:       "2001:db8::",
			description:    "Invalid bits should default to /64",
		},
		{
			name:           "Invalid subnet bits (negative)",
			ip:             "2001:db8::1",
			ipv6SubnetBits: -1,
			expected:       "2001:db8::",
			description:    "Negative bits should default to /64",
		},
		{
			name:           "Invalid IP",
			ip:             "not-an-ip",
			ipv6SubnetBits: 64,
			expected:       "not-an-ip",
			description:    "Invalid IP should return as-is",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeIP(tt.ip, tt.ipv6SubnetBits)
			if result != tt.expected {
				t.Errorf("normalizeIP(%q, %d) = %q, want %q\nDescription: %s",
					tt.ip, tt.ipv6SubnetBits, result, tt.expected, tt.description)
			}
		})
	}
}

// TestIPv6RotationBypassPrevention verifies that attackers cannot bypass
// rate limits by rotating through IPv6 addresses in the same allocation
func TestIPv6RotationBypassPrevention(t *testing.T) {
	// Simulate attacker rotating through multiple IPv6 addresses
	// in the same /64 subnet
	ips := []string{
		"2001:db8:1234:5678:0000:0000:0000:0001",
		"2001:db8:1234:5678:0000:0000:0000:0002",
		"2001:db8:1234:5678:1111:2222:3333:4444",
		"2001:db8:1234:5678:aaaa:bbbb:cccc:dddd",
		"2001:db8:1234:5678:ffff:ffff:ffff:ffff",
	}

	// All should normalize to the same subnet when using /64
	expectedSubnet := "2001:db8:1234:5678::"

	for _, ip := range ips {
		normalized := normalizeIP(ip, 64)
		if normalized != expectedSubnet {
			t.Errorf("IPv6 rotation bypass detected: %q normalized to %q, expected %q",
				ip, normalized, expectedSubnet)
		}
	}

	t.Logf("✅ All %d IPv6 addresses correctly normalized to %q (rotation bypass prevented)",
		len(ips), expectedSubnet)
}

// TestIPv4MappedIPv6Bypass verifies that attackers cannot bypass rate limits
// by switching between IPv4 and IPv4-mapped IPv6 representations
func TestIPv4MappedIPv6Bypass(t *testing.T) {
	testCases := []struct {
		ipv4        string
		ipv6Mapped  string
		description string
	}{
		{
			ipv4:        "192.0.2.1",
			ipv6Mapped:  "::ffff:192.0.2.1",
			description: "Standard IPv4 address",
		},
		{
			ipv4:        "10.0.0.1",
			ipv6Mapped:  "::ffff:10.0.0.1",
			description: "Private IPv4 address",
		},
		{
			ipv4:        "127.0.0.1",
			ipv6Mapped:  "::ffff:127.0.0.1",
			description: "Localhost",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			normalizedIPv4 := normalizeIP(tc.ipv4, 64)
			normalizedIPv6 := normalizeIP(tc.ipv6Mapped, 64)

			if normalizedIPv4 != normalizedIPv6 {
				t.Errorf("IPv4/IPv6 bypass detected:\n  IPv4 %q -> %q\n  IPv6 %q -> %q\nExpected both to normalize to same value",
					tc.ipv4, normalizedIPv4, tc.ipv6Mapped, normalizedIPv6)
			}

			if normalizedIPv4 != tc.ipv4 {
				t.Errorf("IPv4 should normalize to itself, got %q, want %q",
					normalizedIPv4, tc.ipv4)
			}

			t.Logf("✅ %s: Both forms normalize to %q (bypass prevented)",
				tc.description, normalizedIPv4)
		})
	}
}

func TestGetIPv6SubnetBits(t *testing.T) {
	// Test default value
	bits := getIPv6SubnetBits()
	if bits != 64 {
		t.Errorf("Default IPv6 subnet bits should be 64, got %d", bits)
	}
}
