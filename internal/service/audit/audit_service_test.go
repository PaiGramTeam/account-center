package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"paigram/internal/model"
	"paigram/internal/testutil"
)

func TestBuildAuditEventViewIncludesBindingIDAndStructuredMetadata(t *testing.T) {
	view := buildAuditEventView(model.AuditEvent{
		ID:           1,
		Category:     "platform_binding",
		ActorType:    "user",
		ActorUserID:  sql.NullInt64{Int64: 12, Valid: true},
		Action:       "refresh_failed",
		TargetType:   "binding",
		TargetID:     "binding-1",
		BindingID:    sql.NullInt64{Int64: 88, Valid: true},
		Result:       "failure",
		ReasonCode:   "upstream_unavailable",
		RequestID:    "req-1",
		IP:           "192.0.2.1",
		UserAgent:    "go-test",
		MetadataJSON: `{"platform":"mihomo","attempt":2}`,
		CreatedAt:    time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC),
	})

	require.NotNil(t, view.BindingID)
	require.Equal(t, uint64(88), *view.BindingID)
	require.Equal(t, "mihomo", view.Metadata["platform"])
	require.Equal(t, float64(2), view.Metadata["attempt"])
	require.Equal(t, `{"platform":"mihomo","attempt":2}`, view.MetadataJSON)
}

func TestRecordStoresCanonicalAuditMetadata(t *testing.T) {
	db := testutil.OpenMySQLTestDB(t, "audit_service", &model.AuditEvent{})

	actorUserID := uint64(12)
	ownerUserID := uint64(34)
	bindingID := uint64(56)
	require.NoError(t, Record(context.Background(), db, WriteInput{
		Category:    "platform_binding",
		ActorType:   "user",
		ActorUserID: &actorUserID,
		Action:      "binding_refresh",
		TargetType:  "binding",
		TargetID:    "56",
		BindingID:   &bindingID,
		OwnerUserID: &ownerUserID,
		Result:      "failure",
		ReasonCode:  "upstream_unavailable",
		RequestID:   "req-audit-1",
		Metadata: map[string]any{
			"platform": "mihomo",
		},
	}))

	var event model.AuditEvent
	require.NoError(t, db.First(&event).Error)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(event.MetadataJSON), &metadata))
	require.Contains(t, metadata, "actor")
	require.Contains(t, metadata, "target")
	require.Contains(t, metadata, "owner")
	require.Equal(t, "req-audit-1", metadata["request_id"])
	require.Equal(t, "upstream_unavailable", metadata["reason"])
}
