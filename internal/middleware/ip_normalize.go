package middleware

import (
	"net"
	"os"
	"strconv"
)

// normalizeIP normalizes an IP address for consistent rate limiting
// - Converts IPv4-mapped IPv6 addresses to IPv4 (::ffff:192.0.2.1 -> 192.0.2.1)
// - Normalizes IPv6 addresses to canonical form
// - Applies subnet masking to IPv6 addresses to prevent rotation bypass
func normalizeIP(ip string, ipv6SubnetBits int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Invalid IP - return as-is (will fail rate limiting anyway)
		return ip
	}

	// Convert IPv4-mapped IPv6 to IPv4
	// e.g., ::ffff:192.0.2.1 -> 192.0.2.1
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}

	// Handle IPv6 addresses
	if parsed.To16() != nil {
		// Validate subnet bits (must be between 0 and 128)
		if ipv6SubnetBits < 0 || ipv6SubnetBits > 128 {
			ipv6SubnetBits = 64 // Default to /64
		}

		// For individual address tracking (128), return as-is
		if ipv6SubnetBits == 128 {
			return parsed.String()
		}

		// Apply subnet mask to prevent rotation bypass
		// e.g., with /64: 2001:db8:1234:5678::1 -> 2001:db8:1234:5678::
		mask := net.CIDRMask(ipv6SubnetBits, 128)
		subnet := parsed.Mask(mask)
		return subnet.String()
	}

	// Shouldn't reach here, but return normalized form
	return parsed.String()
}

// getIPv6SubnetBits returns the configured IPv6 subnet prefix length
// Can be overridden via IPV6_SUBNET_BITS environment variable
func getIPv6SubnetBits() int {
	// Check environment variable first
	if envBits := os.Getenv("IPV6_SUBNET_BITS"); envBits != "" {
		if bits, err := strconv.Atoi(envBits); err == nil {
			if bits >= 0 && bits <= 128 {
				return bits
			}
		}
	}

	// Default to /64 (typical home/business allocation)
	return 64
}
