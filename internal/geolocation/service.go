package geolocation

import (
	"context"
	"encoding/json"
	"fmt"
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
}

// NewService creates a new geolocation service
func NewService() *Service {
	return &Service{
		cache: make(map[string]*Location),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Lookup performs IP geolocation lookup with caching
func (s *Service) Lookup(ip string) (*Location, error) {
	// Check if it's a valid IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check for local/private IPs
	if isPrivateIP(parsedIP) {
		return &Location{
			City:    "Local",
			Country: "Private Network",
		}, nil
	}

	// Check cache first
	s.cacheMutex.RLock()
	if loc, exists := s.cache[ip]; exists {
		s.cacheMutex.RUnlock()
		return loc, nil
	}
	s.cacheMutex.RUnlock()

	// Fetch from API
	loc, err := s.fetchFromAPI(ip)
	if err != nil {
		return nil, err
	}

	// Cache the result
	s.cacheMutex.Lock()
	s.cache[ip] = loc
	s.cacheMutex.Unlock()

	return loc, nil
}

// fetchFromAPI queries the IP-API.com free service
func (s *Service) fetchFromAPI(ip string) (*Location, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use ip-api.com free tier (no API key required, 45 req/min limit)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,timezone,lat,lon,isp", ip)

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

	// Check for private IP ranges
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
