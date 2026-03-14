//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestAuthPasswordResetRoutesReachableWhenRateLimitEnabled(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, _, _, email, password := registerVerifyAndLogin(t, stack, "password-reset")

	forgotRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/forgot-password", map[string]any{
		"email": email,
	}, nil)
	require.Equal(t, http.StatusOK, forgotRes.Code, forgotRes.Body.String())

	var resetTokenCount int64
	require.NoError(t, stack.DB.Model(&model.PasswordResetToken{}).Where("user_id = ?", userID).Count(&resetTokenCount).Error)
	assert.Equal(t, int64(1), resetTokenCount)

	resetRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/reset-password", map[string]any{
		"token":        "invalid-token",
		"new_password": password + "-new",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resetRes.Code, resetRes.Body.String())
	assert.Equal(t, "INVALID_TOKEN", decodeErrorCode(t, resetRes))
}

func TestProtectedSecurityRoutesReachableForAuthenticatedSelf(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, _, email, password := registerVerifyAndLogin(t, stack, "security-self")
	headers := authHeaders(accessToken)

	addEmailRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/emails", userID), map[string]any{
		"email": fmt.Sprintf("alias-%d@example.com", userID),
	}, headers)
	require.Equal(t, http.StatusCreated, addEmailRes.Code, addEmailRes.Body.String())

	devicesRes := performJSONRequest(t, stack.Router, http.MethodGet, fmt.Sprintf("/api/v1/profiles/%d/devices", userID), nil, headers)
	require.Equal(t, http.StatusOK, devicesRes.Code, devicesRes.Body.String())

	changePasswordRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/password/change", userID), map[string]any{
		"old_password": password,
		"new_password": password + "-updated",
	}, headers)
	require.Equal(t, http.StatusOK, changePasswordRes.Code, changePasswordRes.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password + "-updated",
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
}

func TestSensitiveSecurityRoutesRequireFreshSession(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, refreshToken, _, password := registerVerifyAndLogin(t, stack, "freshness")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("created_at", time.Now().UTC().Add(-10*time.Minute)).Error)

	staleRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/password/change", userID), map[string]any{
		"old_password": password,
		"new_password": password + "-stale",
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, staleRes.Code, staleRes.Body.String())
	assert.Equal(t, "SESSION_NOT_FRESH", decodeErrorCode(t, staleRes))
}

func TestCrossUserRoutesRequirePermissions(t *testing.T) {
	stack := newIntegrationStack(t)

	viewerID, viewerAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "permission-viewer")
	targetID, _, _, _, _ := registerVerifyAndLogin(t, stack, "permission-target")

	headers := authHeaders(viewerAccessToken)

	for _, path := range []string{
		fmt.Sprintf("/api/v1/users/%d", targetID),
		fmt.Sprintf("/api/v1/users/%d/roles", targetID),
		fmt.Sprintf("/api/v1/users/%d/permissions", targetID),
		fmt.Sprintf("/api/v1/users/%d/audit-logs", targetID),
	} {
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		require.Equal(t, http.StatusForbidden, res.Code, "%s => %s", path, res.Body.String())
		assert.Equal(t, "FORBIDDEN", decodeErrorCode(t, res))
	}

	grantPermissionsToUser(t, stack, viewerID,
		model.PermUserRead,
		model.PermRoleRead,
		model.PermPermissionRead,
		model.PermAuditRead,
	)

	for _, path := range []string{
		fmt.Sprintf("/api/v1/users/%d", targetID),
		fmt.Sprintf("/api/v1/users/%d/roles", targetID),
		fmt.Sprintf("/api/v1/users/%d/permissions", targetID),
		fmt.Sprintf("/api/v1/users/%d/audit-logs", targetID),
	} {
		res := performJSONRequest(t, stack.Router, http.MethodGet, path, nil, headers)
		require.Equal(t, http.StatusOK, res.Code, "%s => %s", path, res.Body.String())
	}
}

func TestAdminRoutesRequireAdminRole(t *testing.T) {
	stack := newIntegrationStack(t)

	actorID, actorAccessToken, _, _, _ := registerVerifyAndLogin(t, stack, "admin-actor")
	targetID, _, _, targetEmail, _ := registerVerifyAndLogin(t, stack, "admin-target")

	resetPath := fmt.Sprintf("/api/v1/users/%d/reset-password", targetID)
	body := map[string]any{
		"new_password":        "ResetByAdmin123!",
		"invalidate_sessions": true,
	}
	denied := performJSONRequest(t, stack.Router, http.MethodPost, resetPath, body, authHeaders(actorAccessToken))
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())

	grantAdminRoleToUser(t, stack, actorID)

	allowed := performJSONRequest(t, stack.Router, http.MethodPost, resetPath, body, authHeaders(actorAccessToken))
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    targetEmail,
		"password": "ResetByAdmin123!",
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
}

func TestTwoFactorLifecycle(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, _, _, password := registerVerifyAndLogin(t, stack, "twofa")
	headers := authHeaders(accessToken)

	enableRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/2fa/enable", userID), map[string]any{
		"password": password,
	}, headers)
	require.Equal(t, http.StatusOK, enableRes.Code, enableRes.Body.String())
	enableData := decodeResponseData(t, enableRes)
	secret := enableData["secret"].(string)
	backupCodesRaw := enableData["backup_codes"].([]any)
	require.NotEmpty(t, backupCodesRaw)
	firstBackupCode := backupCodesRaw[0].(string)

	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	confirmRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/2fa/confirm", userID), map[string]any{
		"code": code,
	}, headers)
	require.Equal(t, http.StatusOK, confirmRes.Code, confirmRes.Body.String())

	regenRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/2fa/regenerate-backup-codes", userID), map[string]any{
		"password": password,
	}, headers)
	require.Equal(t, http.StatusOK, regenRes.Code, regenRes.Body.String())
	regenData := decodeResponseData(t, regenRes)
	newBackupCodes := regenData["backup_codes"].([]any)
	require.Len(t, newBackupCodes, 10)
	assert.NotEqual(t, firstBackupCode, newBackupCodes[0].(string))

	disableCode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	disableRes := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/2fa/disable", userID), map[string]any{
		"password": password,
		"code":     disableCode,
	}, headers)
	require.Equal(t, http.StatusOK, disableRes.Code, disableRes.Body.String())

	var twoFactorCount int64
	require.NoError(t, stack.DB.Model(&model.UserTwoFactor{}).Where("user_id = ?", userID).Count(&twoFactorCount).Error)
	assert.Zero(t, twoFactorCount)

	var auditCount int64
	require.NoError(t, stack.DB.Model(&model.AuditLog{}).Where("user_id = ? AND action IN ?", userID, []string{"2fa_enabled", "2fa_disabled", "2fa_backup_codes_regenerated"}).Count(&auditCount).Error)
	assert.Equal(t, int64(3), auditCount)
}

func TestTwoFactorRoutesRequireFreshSession(t *testing.T) {
	stack := newIntegrationStack(t)

	userID, accessToken, refreshToken, _, password := registerVerifyAndLogin(t, stack, "twofa-stale")
	session := requireSessionForRefreshToken(t, stack.DB, refreshToken)
	require.NoError(t, stack.DB.Model(&model.UserSession{}).Where("id = ?", session.ID).Update("created_at", time.Now().UTC().Add(-10*time.Minute)).Error)

	res := performJSONRequest(t, stack.Router, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/2fa/enable", userID), map[string]any{
		"password": password,
	}, authHeaders(accessToken))
	require.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
	assert.Equal(t, "SESSION_NOT_FRESH", decodeErrorCode(t, res))
}

func registerVerifyAndLogin(t *testing.T, stack *integrationStack, prefix string) (uint64, string, string, string, string) {
	t.Helper()

	email := fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
	password := "Password123!"

	registerRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email":        email,
		"password":     password,
		"display_name": "Security Tester",
		"locale":       "en_US",
	}, nil)
	require.Equal(t, http.StatusCreated, registerRes.Code, registerRes.Body.String())
	registerData := decodeResponseData(t, registerRes)
	verificationToken := registerData["verification_token"].(string)

	verifyRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{
		"email": email,
		"token": verificationToken,
	}, nil)
	require.Equal(t, http.StatusOK, verifyRes.Code, verifyRes.Body.String())

	loginRes := performJSONRequest(t, stack.Router, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, map[string]string{"User-Agent": "IntegrationSecurityRoutes/1.0"})
	require.Equal(t, http.StatusOK, loginRes.Code, loginRes.Body.String())
	loginData := decodeResponseData(t, loginRes)

	userID := uint64(loginData["user_id"].(float64))
	accessToken := loginData["access_token"].(string)
	refreshToken := loginData["refresh_token"].(string)

	return userID, accessToken, refreshToken, email, password
}

func authHeaders(accessToken string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + accessToken,
		"User-Agent":    "IntegrationSecurityRoutes/1.0",
	}
}

func decodeErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	errorData := payload["error"].(map[string]any)
	code, _ := errorData["code"].(string)
	return code
}

func grantPermissionsToUser(t *testing.T, stack *integrationStack, userID uint64, permissionNames ...string) {
	t.Helper()

	roleName := fmt.Sprintf("test-role-%d-%d", userID, time.Now().UnixNano())
	role := model.Role{
		Name:        roleName,
		DisplayName: roleName,
		Description: "integration test role",
	}
	require.NoError(t, stack.DB.Create(&role).Error)

	for _, permName := range permissionNames {
		permission := model.Permission{
			Name:        permName,
			Resource:    permissionResource(permName),
			Action:      permissionAction(permName),
			Description: "integration test permission",
		}
		require.NoError(t, stack.DB.Where(model.Permission{Name: permName}).FirstOrCreate(&permission).Error)
		rolePermission := model.RolePermission{RoleID: role.ID, PermissionID: permission.ID}
		require.NoError(t, stack.DB.Where(&rolePermission).FirstOrCreate(&rolePermission).Error)
	}

	userRole := model.UserRole{UserID: userID, RoleID: role.ID, GrantedBy: userID}
	require.NoError(t, stack.DB.Create(&userRole).Error)
}

func grantAdminRoleToUser(t *testing.T, stack *integrationStack, userID uint64) {
	t.Helper()

	role := model.Role{
		Name:        model.RoleAdmin,
		DisplayName: "Admin",
		Description: "integration test admin role",
		IsSystem:    true,
	}
	require.NoError(t, stack.DB.Where(model.Role{Name: model.RoleAdmin}).FirstOrCreate(&role).Error)
	userRole := model.UserRole{UserID: userID, RoleID: role.ID, GrantedBy: userID}
	require.NoError(t, stack.DB.Where(model.UserRole{UserID: userID, RoleID: role.ID}).Assign(model.UserRole{GrantedBy: userID}).FirstOrCreate(&userRole).Error)
}

func permissionResource(name string) string {
	parts := splitPermission(name)
	return parts[0]
}

func permissionAction(name string) string {
	parts := splitPermission(name)
	return parts[1]
}

func splitPermission(name string) []string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts
	}
	return []string{"custom", "custom"}
}
