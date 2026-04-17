package platform

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	"paigram/internal/testutil"
)

type fakePlatformHealthChecker struct {
	result runtimeProbeResult
	calls  int

	lastEndpoint string
}

func (f *fakePlatformHealthChecker) Check(_ context.Context, endpoint string) runtimeProbeResult {
	f.calls++
	f.lastEndpoint = endpoint
	return f.result
}

func TestPlatformServiceCreatePlatformService(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_admin_create", &model.PlatformService{})
	svc := NewServiceGroup(db).PlatformService
	checker := &fakePlatformHealthChecker{result: runtimeProbeResult{State: RuntimeStateHealthy, CheckedAt: time.Now().UTC()}}
	svc.SetHealthChecker(checker)

	view, err := svc.CreatePlatformService(context.Background(), CreatePlatformServiceInput{
		PlatformKey:      "mihomo",
		DisplayName:      "Mihomo",
		ServiceKey:       "platform-mihomo-service",
		ServiceAudience:  "platform-mihomo-service",
		DiscoveryType:    "static",
		Endpoint:         "127.0.0.1:9000",
		Enabled:          true,
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object"},
	})
	require.NoError(t, err)
	require.Equal(t, "mihomo", view.PlatformKey)
	require.Equal(t, ConfigStateEnabled, view.ConfigState)
	require.Equal(t, RuntimeStateHealthy, view.RuntimeState)
	require.Equal(t, 1, checker.calls)
}

func TestPlatformServiceCreatePlatformServiceTrimsPersistedFields(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_trimmed_create", &model.PlatformService{})
	svc := NewServiceGroup(db).PlatformService
	checker := &fakePlatformHealthChecker{result: runtimeProbeResult{State: RuntimeStateHealthy, CheckedAt: time.Now().UTC()}}
	svc.SetHealthChecker(checker)

	view, err := svc.CreatePlatformService(context.Background(), CreatePlatformServiceInput{
		PlatformKey:      " mihomo ",
		DisplayName:      " Mihomo ",
		ServiceKey:       " platform-mihomo-service ",
		ServiceAudience:  " platform-mihomo-service ",
		DiscoveryType:    " static ",
		Endpoint:         " 127.0.0.1:9000 ",
		Enabled:          true,
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object"},
	})
	require.NoError(t, err)
	require.Equal(t, "mihomo", view.PlatformKey)
	require.Equal(t, "Mihomo", view.DisplayName)
	require.Equal(t, "platform-mihomo-service", view.ServiceKey)
	require.Equal(t, "platform-mihomo-service", view.ServiceAudience)
	require.Equal(t, "static", view.DiscoveryType)
	require.Equal(t, "127.0.0.1:9000", view.Endpoint)
	require.Equal(t, "127.0.0.1:9000", checker.lastEndpoint)

	var persisted model.PlatformService
	require.NoError(t, db.First(&persisted, view.ID).Error)
	require.Equal(t, "mihomo", persisted.PlatformKey)
	require.Equal(t, "Mihomo", persisted.DisplayName)
	require.Equal(t, "platform-mihomo-service", persisted.ServiceKey)
	require.Equal(t, "platform-mihomo-service", persisted.ServiceAudience)
	require.Equal(t, "static", persisted.DiscoveryType)
	require.Equal(t, "127.0.0.1:9000", persisted.Endpoint)
}

func TestPlatformServiceCheckPlatformServiceDisabledSkipsProbe(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_admin_check_disabled", &model.PlatformService{})
	row := model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              false,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}
	require.NoError(t, db.Create(&row).Error)
	require.NoError(t, db.Model(&row).Update("enabled", false).Error)

	svc := NewServiceGroup(db).PlatformService
	checker := &fakePlatformHealthChecker{result: runtimeProbeResult{State: RuntimeStateHealthy, CheckedAt: time.Now().UTC()}}
	svc.SetHealthChecker(checker)

	view, err := svc.CheckPlatformService(context.Background(), row.ID)
	require.NoError(t, err)
	require.Equal(t, ConfigStateDisabled, view.ConfigState)
	require.Equal(t, RuntimeStateDisabled, view.RuntimeState)
	require.Zero(t, checker.calls)
}

func TestPlatformServiceDeletePlatformServiceRejectsReferencedPlatform(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_admin_delete_referenced", &model.PlatformService{}, &model.User{}, &model.PlatformAccountRef{})
	row := model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}
	require.NoError(t, db.Create(&row).Error)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	require.NoError(t, db.Create(&model.PlatformAccountRef{
		UserID:             owner.ID,
		Platform:           "mihomo",
		PlatformServiceKey: "platform-mihomo-service",
		PlatformAccountID:  "hoyo_ref_11_10001",
		DisplayName:        "Traveler",
		Status:             model.PlatformAccountRefStatusActive,
	}).Error)

	svc := NewServiceGroup(db).PlatformService
	err := svc.DeletePlatformService(context.Background(), row.ID)
	require.ErrorIs(t, err, ErrPlatformServiceReferenced)
}

func TestPlatformServiceUpdatePlatformServiceRejectsIdentityChanges(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "platform_registry_update_identity", &model.PlatformService{})
	row := model.PlatformService{
		PlatformKey:          "mihomo",
		DisplayName:          "Mihomo",
		ServiceKey:           "platform-mihomo-service",
		ServiceAudience:      "platform-mihomo-service",
		DiscoveryType:        "static",
		Endpoint:             "127.0.0.1:9000",
		Enabled:              true,
		SupportedActionsJSON: `[]`,
		CredentialSchemaJSON: `{}`,
	}
	require.NoError(t, db.Create(&row).Error)

	svc := NewServiceGroup(db).PlatformService
	_, err := svc.UpdatePlatformService(context.Background(), row.ID, UpdatePlatformServiceInput{
		PlatformKey:      "zenless",
		DisplayName:      "Mihomo Admin",
		ServiceKey:       "platform-zenless-service",
		ServiceAudience:  "platform-mihomo-service",
		DiscoveryType:    "static",
		Endpoint:         "127.0.0.1:9001",
		Enabled:          true,
		SupportedActions: []string{"bind_credential"},
		CredentialSchema: map[string]any{"type": "object"},
	})
	require.ErrorIs(t, err, ErrInvalidPlatformServiceConfig)

	var persisted model.PlatformService
	require.NoError(t, db.First(&persisted, row.ID).Error)
	require.Equal(t, "mihomo", persisted.PlatformKey)
	require.Equal(t, "platform-mihomo-service", persisted.ServiceKey)
}
