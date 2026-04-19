package systemconfig

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
	"paigram/internal/testutil"
)

func TestSettingsServiceConcurrentPatchesPreserveBothUpdates(t *testing.T) {
	db := openSystemConfigTestDB(t)
	service := NewSettingsService(db)

	ctx := context.Background()
	start := make(chan struct{})
	errCh := make(chan error, 2)

	var wg sync.WaitGroup
	for _, patch := range []map[string]any{
		{"site_name": "PaiGram"},
		{"site_domain": "account.example.com"},
	} {
		wg.Add(1)
		go func(p map[string]any) {
			defer wg.Done()
			<-start
			_, err := service.PatchSite(ctx, p, 100)
			errCh <- err
		}(patch)
	}

	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	view, err := service.GetSite(ctx)
	require.NoError(t, err)
	require.Equal(t, "PaiGram", view.Settings["site_name"])
	require.Equal(t, "account.example.com", view.Settings["site_domain"])
	require.Equal(t, uint64(2), view.Version)

	var auditCount int64
	require.NoError(t, db.Model(&model.AuditEvent{}).Where("category = ?", "system_settings").Count(&auditCount).Error)
	require.Equal(t, int64(2), auditCount)
}

func TestSettingsServiceAuditMetadataRedactsPatchedValues(t *testing.T) {
	db := openSystemConfigTestDB(t)
	service := NewSettingsService(db)

	view, err := service.PatchEmail(context.Background(), map[string]any{
		"smtp_host":     "smtp.example.com",
		"smtp_password": "super-secret",
	}, 100)
	require.NoError(t, err)
	require.Equal(t, "smtp.example.com", view.Settings["smtp_host"])

	var audit model.AuditEvent
	require.NoError(t, db.Where("category = ? AND target_id = ?", "system_settings", DomainEmail).Order("id DESC").First(&audit).Error)
	require.NotContains(t, audit.MetadataJSON, "super-secret")
	require.NotContains(t, audit.MetadataJSON, "smtp.example.com")

	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.MetadataJSON), &metadata))
	require.Equal(t, DomainEmail, metadata["domain"])
	require.ElementsMatch(t, []any{"smtp_host", "smtp_password"}, metadata["changed_keys"].([]any))
	_, hasSettings := metadata["settings"]
	require.False(t, hasSettings)
}

func TestLegalServiceListsDraftsAndHistoricalRevisions(t *testing.T) {
	db := openSystemConfigTestDB(t)
	service := NewLegalService(db)

	ctx := context.Background()
	_, err := service.UpsertDocuments(ctx, []UpsertLegalDocumentInput{
		{DocumentType: "terms", Version: "2026-04-01", Title: "Terms v1", Content: "published", Published: true},
		{DocumentType: "terms", Version: "2026-04-20-draft", Title: "Terms draft", Content: "draft", Published: false},
		{DocumentType: "privacy", Version: "2026-04-19", Title: "Privacy v1", Content: "privacy", Published: true},
	}, 7)
	require.NoError(t, err)

	documents, err := service.ListDocuments(ctx)
	require.NoError(t, err)
	require.Len(t, documents, 3)
	require.Equal(t, "privacy", documents[0].DocumentType)
	require.Equal(t, "terms", documents[1].DocumentType)
	require.Equal(t, "2026-04-20-draft", documents[1].Version)
	require.False(t, documents[1].Published)
	require.Equal(t, "2026-04-01", documents[2].Version)
	require.True(t, documents[2].Published)

	published, err := service.ListPublishedDocuments(ctx)
	require.NoError(t, err)
	require.Len(t, published, 2)
}

func openSystemConfigTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := testutil.OpenMySQLTestDB(t, "systemconfig", &model.SystemConfigEntry{}, &model.LegalDocument{}, &model.AuditEvent{})
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	return db
}
