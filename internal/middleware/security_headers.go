// Package middleware: V10 — security response headers.
//
// SecurityHeaders sets a small set of broadly-applicable HTTP response
// headers that defend against MIME sniffing, clickjacking, referrer
// leaks, and (over HTTPS) TLS downgrade. The middleware is intended to
// run on every response, including CORS-rejected and error responses,
// so it must be installed BEFORE the CORS middleware in the Gin chain.
//
// HSTS is emitted only when the request is served over a TLS
// connection terminated in this process (`c.Request.TLS != nil`), or
// when AssumeHTTPS is configured. We deliberately do NOT honor
// `X-Forwarded-Proto` headers, which are forgeable by any client when
// `app.trusted_proxies` is not configured to filter them. Operators
// running behind an HTTPS-terminating proxy must opt in via
// `security.security_headers.assume_https = true`.
package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersConfig configures the security-headers middleware.
type SecurityHeadersConfig struct {
	// HSTSMaxAgeSeconds is the max-age value for Strict-Transport-Security.
	// Defaults to 31536000 (1 year) when zero.
	HSTSMaxAgeSeconds int
	// HSTSIncludeSub appends "; includeSubDomains" to the HSTS header.
	// Default false. Turning this on is irrecoverable for the parent
	// domain for the duration of max-age, so leave it off until every
	// subdomain is HTTPS-only.
	HSTSIncludeSub bool
	// CSP is the Content-Security-Policy header value. Defaults to
	// "default-src 'self'" when empty. Backends that serve any HTML
	// (even error pages) should keep at least 'self' so same-origin
	// resources can render.
	CSP string
	// AssumeHTTPS instructs the middleware to emit HSTS even though the
	// request reached this process over plain HTTP. Set to true ONLY if
	// your reverse proxy strips upstream TLS and you trust ALL traffic
	// reaches the proxy over HTTPS. The middleware will not parse
	// `X-Forwarded-Proto` from request headers (which can be spoofed by
	// any client when `app.trusted_proxies` is empty); operators must
	// opt in explicitly.
	AssumeHTTPS bool
}

// SecurityHeaders returns a Gin middleware that emits baseline security
// response headers. See SecurityHeadersConfig for tunables.
func SecurityHeaders(cfg SecurityHeadersConfig) gin.HandlerFunc {
	if cfg.CSP == "" {
		cfg.CSP = "default-src 'self'"
	}
	if cfg.HSTSMaxAgeSeconds == 0 {
		cfg.HSTSMaxAgeSeconds = 31536000
	}
	hstsValue := "max-age=" + strconv.Itoa(cfg.HSTSMaxAgeSeconds)
	if cfg.HSTSIncludeSub {
		hstsValue += "; includeSubDomains"
	}

	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", cfg.CSP)

		// Emit HSTS only when we know the connection is secured —
		// either TLS terminated in this process, or the operator
		// opted in via AssumeHTTPS. We deliberately do NOT trust
		// `X-Forwarded-Proto` because it is forgeable by any client
		// when no proxy filter is in place; emitting HSTS in
		// response to a spoofed header would lock victim browsers
		// out of plain-HTTP access to the host for max-age.
		if c.Request.TLS != nil || cfg.AssumeHTTPS {
			h.Set("Strict-Transport-Security", hstsValue)
		}

		c.Next()
	}
}
