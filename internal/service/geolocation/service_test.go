package geolocation

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookupRejectsInvalidIP(t *testing.T) {
	s := NewService()
	_, err := s.Lookup("not-an-ip")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid IP address")
}

func TestLookupReturnsLocalForPrivateIPs(t *testing.T) {
	s := NewService()

	cases := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"fc00::1",
		"::1",
	}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			loc, err := s.Lookup(ip)
			require.NoError(t, err)
			require.Equal(t, "Local", loc.City)
			require.Equal(t, "Private Network", loc.Country)
		})
	}
}

func TestLookupCachesPublicIPResult(t *testing.T) {
	var calls int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		fmt.Fprint(w, `{"status":"success","country":"Japan","countryCode":"JP","region":"13","regionName":"Tokyo","city":"Tokyo","timezone":"Asia/Tokyo","lat":35.0,"lon":139.0,"isp":"Test ISP"}`)
	}))
	defer mock.Close()

	s := NewService()
	s.SetHTTPClient(mock.Client())
	s.SetAPIBaseURL(mock.URL)

	first, err := s.Lookup("8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, "Tokyo", first.City)
	require.Equal(t, "Japan", first.Country)

	second, err := s.Lookup("8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.EqualValues(t, 1, atomic.LoadInt32(&calls), "second lookup must hit cache, not the upstream")
}

func TestLookupReturnsErrorOnUpstreamNonOK(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer mock.Close()

	s := NewService()
	s.SetHTTPClient(mock.Client())
	s.SetAPIBaseURL(mock.URL)

	_, err := s.Lookup("8.8.8.8")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected status code")
}

func TestLookupReturnsErrorOnUpstreamFailureStatus(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"fail","message":"reserved range"}`)
	}))
	defer mock.Close()

	s := NewService()
	s.SetHTTPClient(mock.Client())
	s.SetAPIBaseURL(mock.URL)

	_, err := s.Lookup("8.8.8.8")
	require.Error(t, err)
	require.Contains(t, err.Error(), "API error")
}

func TestClearCacheForcesRefetch(t *testing.T) {
	var calls int32
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		fmt.Fprint(w, `{"status":"success","country":"Japan","countryCode":"JP","city":"Tokyo"}`)
	}))
	defer mock.Close()

	s := NewService()
	s.SetHTTPClient(mock.Client())
	s.SetAPIBaseURL(mock.URL)

	_, err := s.Lookup("8.8.8.8")
	require.NoError(t, err)
	s.ClearCache()
	_, err = s.Lookup("8.8.8.8")
	require.NoError(t, err)
	require.EqualValues(t, 2, atomic.LoadInt32(&calls))
}

func TestSetHTTPClientIgnoresNil(t *testing.T) {
	s := NewService()
	original := s.httpClient
	s.SetHTTPClient(nil)
	require.Same(t, original, s.httpClient, "nil client must be ignored, not overwrite the existing client")
}

func TestSetAPIBaseURLIgnoresEmpty(t *testing.T) {
	s := NewService()
	originalBase := s.apiBaseURL
	s.SetAPIBaseURL("")
	require.Equal(t, originalBase, s.apiBaseURL, "empty base must be ignored, not overwrite the existing base")
}

func TestIsPrivateIP(t *testing.T) {
	private := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "fc00::1", "::1", "fe80::1"}
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}

	for _, ip := range private {
		require.Truef(t, isPrivateIP(net.ParseIP(ip)), "expected %s to be private", ip)
	}
	for _, ip := range public {
		require.Falsef(t, isPrivateIP(net.ParseIP(ip)), "expected %s to be public", ip)
	}
}

func TestLocationString(t *testing.T) {
	require.Equal(t, "Tokyo, Japan", (&Location{City: "Tokyo", Country: "Japan"}).String())
	require.Equal(t, "Japan", (&Location{Country: "Japan"}).String())
	require.Equal(t, "Unknown", (&Location{}).String())
}
