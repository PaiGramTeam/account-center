package audit

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"paigram/internal/model"
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
