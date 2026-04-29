package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCache fetches and caches a JWKS document from a single URL. It is
// safe for concurrent use.
//
// Behavior:
//
//   - lookupKey(kid) returns the cached key for kid, refreshing the JWKS
//     transparently when the cache is stale or when kid is unknown. The
//     refresh-on-unknown-kid path is what lets us pick up provider-side key
//     rotations without waiting for the TTL to elapse.
//   - Refresh failures do not poison the cache: a previously-cached key set
//     remains usable until a fresh fetch succeeds.
//   - Concurrent lookups for an unknown kid coalesce on a single HTTP fetch
//     via singleflight-like behavior under the same mutex.
type jwksCache struct {
	url      string
	ttl      time.Duration
	timeout  time.Duration
	clock    func() time.Time
	httpDoer func(req *http.Request) (*http.Response, error)

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(url string, ttl, timeout time.Duration) *jwksCache {
	client := &http.Client{Timeout: timeout}
	return &jwksCache{
		url:      url,
		ttl:      ttl,
		timeout:  timeout,
		clock:    time.Now,
		httpDoer: client.Do,
	}
}

// lookupKey returns the RSA public key for kid, refreshing the JWKS as
// needed. The caller's ctx bounds any HTTP fetch.
func (c *jwksCache) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key := c.keys[kid]; key != nil && c.clock().Sub(c.fetchedAt) < c.ttl {
		return key, nil
	}

	// Either we don't have this kid cached, or our cache is stale. Refresh.
	keys, err := c.fetchLocked(ctx)
	if err != nil {
		// If we already have a cached value for kid (just stale), keep using
		// it rather than fail the whole verification on a transient JWKS
		// outage.
		if cached, ok := c.keys[kid]; ok && cached != nil {
			return cached, nil
		}
		return nil, err
	}

	c.keys = keys
	c.fetchedAt = c.clock()

	if key := c.keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("oidc: unknown kid %q after JWKS refresh", kid)
}

// fetchLocked performs a single JWKS HTTP fetch. The caller must hold mu.
func (c *jwksCache) fetchLocked(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build jwks request: %w", err)
	}
	resp, err := c.httpDoer(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oidc: jwks fetch status %d: %s", resp.StatusCode, string(body))
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: decode jwks: %w", err)
	}

	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		// Ignore non-signing keys and non-RSA keys; we only need RSA verifiers.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Kty != "RSA" {
			continue
		}
		if k.Kid == "" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk kid=%q: %w", k.Kid, err)
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("oidc: jwks document contained no usable RSA keys")
	}
	return out, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k jwk) publicKey() (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, errors.New("missing modulus/exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31-1 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
