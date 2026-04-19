//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"paigram/internal/response"
)

func performJSONRequest(t *testing.T, handler http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	return performJSONRequestFromIP(t, handler, method, path, body, headers, "192.0.2.1:12345")
}

func performJSONRequestFromIP(t *testing.T, handler http.Handler, method, path string, body any, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		payload, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(payload))
	}

	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func decodeResponseData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var resp response.Response
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resp))
	if resp.Data == nil {
		t.Fatalf("response data is nil, status=%d, body=%s", recorder.Code, recorder.Body.String())
	}
	data, ok := resp.Data.(map[string]any)
	require.True(t, ok, "expected map response data, got %T", resp.Data)
	return data
}
