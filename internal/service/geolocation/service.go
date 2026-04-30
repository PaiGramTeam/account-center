package geolocation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Location represents geographic location information
type Location struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Timezone    string  `json:"timezone"`
	Latitude    float64 `json:"lat"`
	Longitude   float64 `json:"lon"`
	ISP         string  `json:"isp"`
}

// String returns a human-readable location string
func (l *Location) String() string {
	if l.City != "" && l.Country != "" {
		return fmt.Sprintf("%s, %s", l.City, l.Country)
	}
	if l.Country != "" {
		return l.Country
	}
	return "Unknown"
}

// Service provides IP geolocation lookup
type Service struct {
	cache      map[string]*Location
	cacheMutex sync.RWMutex
	httpClient *http.Client
	apiBaseURL string
}

// ipAPIWarningOnce guarantees the V19 plain-HTTP warning is logged
// once per process, no matter how many times NewService is invoked
// (the constructor may be invoked from multiple call sites at startup).
var ipAPIWarningOnce sync.Once

// NewService creates a new geolocation service.
//
// V19 — known limitation: the free ip-api.com tier is HTTP-only. Each
// call leaks the queried IP to any on-path observer, and an active
// MITM can tamper with the response, e.g. to mislabel a login as
// originating from a trusted location. For this pre-production cut we
// keep ip-api.com (option c from the V19 review) and emit a one-shot
// startup warning so operators can plan a provider migration. Replace
// the upstream URL via SetAPIBaseURL/SetHTTPClient when wiring up
// configurable providers.
func NewService() *Service {
	ipAPIWarningOnce.Do(func() {
		log.Printf("[security] WARNING: ip-api.com is queried over plain HTTP; " +
			"geolocation results can be tampered with by MITM. " +
			"Configure a TLS-supporting provider when available (V19).")
	})
	return &Service{
		cache: make(map[string]*Location),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		apiBaseURL: "http://ip-api.com",
	}
}

// SetHTTPClient swaps the underlying HTTP client. Intended for tests
// that point fetchFromAPI at a httptest server. Not safe to call
// concurrently with Lookup; call once during construction/startup.
func (s *Service) SetHTTPClient(c *http.Client) {
	if c != nil {
		s.httpClient = c
	}
}

// SetAPIBaseURL overrides the upstream base URL. Intended for tests
// and future configurable provider support. Must NOT include a path
// or trailing slash. Not safe to call concurrently with Lookup; call
// once during construction/startup.
func (s *Service) SetAPIBaseURL(base string) {
	if base != "" {
		s.apiBaseURL = base
	}
}

// Lookup performs IP geolocation lookup with caching
func (s *Service) Lookup(ip string) (*Location, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	if isPrivateIP(parsedIP) {
		return &Location{
			City:    "Local",
			Country: "Private Network",
		}, nil
	}

	s.cacheMutex.RLock()
	if loc, exists := s.cache[ip]; exists {
		s.cacheMutex.RUnlock()
		return loc, nil
	}
	s.cacheMutex.RUnlock()

	loc, err := s.fetchFromAPI(ip)
	if err != nil {
		return nil, err
	}

	s.cacheMutex.Lock()
	s.cache[ip] = loc
	s.cacheMutex.Unlock()

	return loc, nil
}

// fetchFromAPI queries the IP-API.com free service.
//
// SECURITY (V19): the free tier of ip-api.com only supports plain HTTP.
// HTTPS requires a paid pro.ip-api.com plan. The MITM risk is bounded:
// the queried IP is already known to the service, and tampered
// responses degrade only the geolocation-based audit signal — auth and
// session decisions are not gated on this output. See NewService for
// the loud startup warning.
func (s *Service) fetchFromAPI(ip string) (*Location, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/json/%s?fields=status,message,country,countryCode,region,regionName,city,timezone,lat,lon,isp", s.apiBaseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Timezone    string  `json:"timezone"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("API error: %s", result.Message)
	}

	return &Location{
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Region:      result.Region,
		RegionName:  result.RegionName,
		City:        result.City,
		Timezone:    result.Timezone,
		Latitude:    result.Lat,
		Longitude:   result.Lon,
		ISP:         result.ISP,
	}, nil
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 ULA
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// ClearCache clears the location cache
func (s *Service) ClearCache() {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()
	s.cache = make(map[string]*Location)
}
