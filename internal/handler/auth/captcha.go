package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"paigram/internal/config"
)

const (
	turnstileActionRegister = "register"
	turnstileActionLogin    = "login"

	turnstileTokenMaxLength = 2048
)

type captchaVerifier interface {
	Enabled() bool
	Verify(ctx context.Context, req captchaVerifyRequest) (*captchaVerifyResult, error)
}

type captchaVerifyRequest struct {
	Token          string
	RemoteIP       string
	ExpectedAction string
}

type captchaVerifyResult struct {
	Success    bool
	Action     string
	Hostname   string
	ErrorCodes []string
}

type turnstileVerifier struct {
	secretKey        string
	verifyURL        string
	expectedHostname string
	httpClient       *http.Client
}

type turnstileSiteVerifyResponse struct {
	Success    bool     `json:"success"`
	Action     string   `json:"action"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

func newCaptchaVerifier(cfg config.TurnstileConfig) captchaVerifier {
	if !cfg.Enabled || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil
	}

	timeout := time.Duration(cfg.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	verifyURL := strings.TrimSpace(cfg.VerifyURL)
	if verifyURL == "" {
		verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	}

	return &turnstileVerifier{
		secretKey:        strings.TrimSpace(cfg.SecretKey),
		verifyURL:        verifyURL,
		expectedHostname: strings.TrimSpace(cfg.ExpectedHostname),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (v *turnstileVerifier) Enabled() bool {
	return v != nil && v.secretKey != ""
}

func (v *turnstileVerifier) Verify(ctx context.Context, req captchaVerifyRequest) (*captchaVerifyResult, error) {
	if !v.Enabled() {
		return nil, fmt.Errorf("captcha verifier disabled")
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		return &captchaVerifyResult{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}
	if len(token) > turnstileTokenMaxLength {
		return &captchaVerifyResult{Success: false, ErrorCodes: []string{"invalid-input-response"}}, nil
	}

	form := url.Values{}
	form.Set("secret", v.secretKey)
	form.Set("response", token)
	if ip := strings.TrimSpace(req.RemoteIP); ip != "" {
		form.Set("remoteip", ip)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build turnstile request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpResp, err := v.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call turnstile siteverify: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("turnstile siteverify returned status %d", httpResp.StatusCode)
	}

	var resp turnstileSiteVerifyResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode turnstile response: %w", err)
	}

	result := &captchaVerifyResult{
		Success:    resp.Success,
		Action:     resp.Action,
		Hostname:   resp.Hostname,
		ErrorCodes: resp.ErrorCodes,
	}

	if !result.Success {
		return result, nil
	}
	if expectedAction := strings.TrimSpace(req.ExpectedAction); expectedAction != "" && result.Action != "" && result.Action != expectedAction {
		return &captchaVerifyResult{Success: false, Action: result.Action, Hostname: result.Hostname, ErrorCodes: []string{"action-mismatch"}}, nil
	}
	if v.expectedHostname != "" && result.Hostname != "" && result.Hostname != v.expectedHostname {
		return &captchaVerifyResult{Success: false, Action: result.Action, Hostname: result.Hostname, ErrorCodes: []string{"hostname-mismatch"}}, nil
	}

	return result, nil
}
