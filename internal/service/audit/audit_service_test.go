package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
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

// TestNullUint64ClampsAboveMaxInt64 guards the CWE-197 mitigation: when a
// uint64 exceeds math.MaxInt64 we must not silently wrap to a negative
// int64. We clamp to MaxInt64 instead so audit rows never hold a corrupted
// numeric value.
func TestNullUint64ClampsAboveMaxInt64(t *testing.T) {
	cases := []struct {
		name string
		in   uint64
		want sql.NullInt64
	}{
		{"zero", 0, sql.NullInt64{Int64: 0, Valid: true}},
		{"small", 42, sql.NullInt64{Int64: 42, Valid: true}},
		{"max int64 boundary", math.MaxInt64, sql.NullInt64{Int64: math.MaxInt64, Valid: true}},
		{"above max int64 clamps", math.MaxInt64 + 1, sql.NullInt64{Int64: math.MaxInt64, Valid: true}},
		{"max uint64 clamps", math.MaxUint64, sql.NullInt64{Int64: math.MaxInt64, Valid: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nullUint64(tc.in)
			require.Equal(t, tc.want, got)
			require.GreaterOrEqual(t, got.Int64, int64(0),
				"nullUint64 must never produce a negative int64 (CWE-197)")
		})
	}
}
