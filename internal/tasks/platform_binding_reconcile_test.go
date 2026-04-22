package tasks

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"paigram/internal/model"
)

type fakePlatformBindingScanner struct {
	candidates  []platformBindingRepairCandidate
	err         error
	staleBefore time.Time
}

func (f *fakePlatformBindingScanner) ListCandidates(staleBefore time.Time) ([]platformBindingRepairCandidate, error) {
	f.staleBefore = staleBefore
	if f.err != nil {
		return nil, f.err
	}
	return append([]platformBindingRepairCandidate(nil), f.candidates...), nil
}

type fakeAsynqEnqueuer struct {
	tasks []*asynq.Task
	err   error
}

func (f *fakeAsynqEnqueuer) Enqueue(task *asynq.Task, _ ...asynq.Option) (*asynq.TaskInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tasks = append(f.tasks, task)
	return &asynq.TaskInfo{}, nil
}

type fakeProjectionRepairer struct {
	bindingID uint64
	err       error
}

func (f *fakeProjectionRepairer) RepairProjection(_ context.Context, bindingID uint64) (*model.PlatformAccountBinding, error) {
	f.bindingID = bindingID
	if f.err != nil {
		return nil, f.err
	}
	return &model.PlatformAccountBinding{ID: bindingID}, nil
}

type fakeDeleteRepairer struct {
	bindingID uint64
	err       error
}

func (f *fakeDeleteRepairer) RepairDeleteFailedBinding(_ context.Context, bindingID uint64) error {
	f.bindingID = bindingID
	return f.err
}

func TestPlatformBindingReconcileHandlerEnqueuesProjectionAndDeleteRepairs(t *testing.T) {
	scanner := &fakePlatformBindingScanner{candidates: []platformBindingRepairCandidate{
		{BindingID: 101},
		{BindingID: 202, Status: model.PlatformAccountBindingStatusDeleteFailed},
	}}
	enqueuer := &fakeAsynqEnqueuer{}
	handler := NewPlatformBindingReconcileHandlerWithScanner(scanner, enqueuer)
	task, err := NewPlatformBindingReconcileTask()
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.NoError(t, err)
	require.Len(t, enqueuer.tasks, 2)
	assert.Equal(t, TypePlatformBindingProjectionRepair, enqueuer.tasks[0].Type())
	assert.Equal(t, TypePlatformBindingDeleteRepair, enqueuer.tasks[1].Type())
	assert.False(t, scanner.staleBefore.IsZero())
}

func TestPlatformBindingProjectionRepairHandlerRepairsOneBinding(t *testing.T) {
	repairer := &fakeProjectionRepairer{}
	handler := NewPlatformBindingProjectionRepairHandlerWithRepairer(repairer)
	task, err := NewPlatformBindingProjectionRepairTask(404)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.NoError(t, err)
	assert.Equal(t, uint64(404), repairer.bindingID)
}

func TestPlatformBindingDeleteRepairHandlerRepairsOneBinding(t *testing.T) {
	repairer := &fakeDeleteRepairer{}
	handler := NewPlatformBindingDeleteRepairHandlerWithRepairer(repairer)
	task, err := NewPlatformBindingDeleteRepairTask(505)
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.NoError(t, err)
	assert.Equal(t, uint64(505), repairer.bindingID)
}

func TestPlatformBindingReconcileHandlerReturnsEnqueueError(t *testing.T) {
	scanner := &fakePlatformBindingScanner{candidates: []platformBindingRepairCandidate{{BindingID: 101}}}
	enqueuer := &fakeAsynqEnqueuer{err: errors.New("redis down")}
	handler := NewPlatformBindingReconcileHandlerWithScanner(scanner, enqueuer)
	task, err := NewPlatformBindingReconcileTask()
	require.NoError(t, err)

	err = handler.ProcessTask(context.Background(), task)
	require.EqualError(t, err, "enqueue reconcile task for binding 101: redis down")
}

func TestPlatformBindingReconcileScannerFindsDeleteFailedAndStaleBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE platform_account_bindings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			owner_user_id INTEGER NOT NULL,
			platform TEXT NOT NULL,
			external_account_key TEXT,
			platform_service_key TEXT NOT NULL,
			display_name TEXT NOT NULL,
			status TEXT NOT NULL,
			status_reason_code TEXT,
			status_reason_message TEXT,
			primary_profile_id INTEGER,
			last_validated_at DATETIME NULL,
			last_synced_at DATETIME NULL,
			created_at DATETIME NULL,
			updated_at DATETIME NULL,
			deleted_at DATETIME NULL
		)
	`).Error)
	require.NoError(t, db.Create(&[]model.PlatformAccountBinding{
		{
			OwnerUserID:        1,
			Platform:           "mihomo",
			ExternalAccountKey: sql.NullString{String: "cn:stale", Valid: true},
			PlatformServiceKey: "platform-mihomo-service",
			DisplayName:        "Stale",
			Status:             model.PlatformAccountBindingStatusActive,
			LastSyncedAt:       sql.NullTime{Time: time.Now().UTC().Add(-48 * time.Hour), Valid: true},
			LastValidatedAt:    sql.NullTime{Time: time.Now().UTC().Add(-48 * time.Hour), Valid: true},
		},
		{
			OwnerUserID:        1,
			Platform:           "mihomo",
			ExternalAccountKey: sql.NullString{String: "cn:delete", Valid: true},
			PlatformServiceKey: "platform-mihomo-service",
			DisplayName:        "Delete Failed",
			Status:             model.PlatformAccountBindingStatusDeleteFailed,
		},
		{
			OwnerUserID:        1,
			Platform:           "mihomo",
			ExternalAccountKey: sql.NullString{String: "cn:fresh", Valid: true},
			PlatformServiceKey: "platform-mihomo-service",
			DisplayName:        "Fresh",
			Status:             model.PlatformAccountBindingStatusActive,
			LastSyncedAt:       sql.NullTime{Time: time.Now().UTC(), Valid: true},
			LastValidatedAt:    sql.NullTime{Time: time.Now().UTC(), Valid: true},
		},
	}).Error)

	scanner := &platformBindingReconcileScanner{db: db}
	candidates, err := scanner.ListCandidates(time.Now().UTC().Add(-24 * time.Hour))
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	assert.Equal(t, model.PlatformAccountBindingStatusActive, candidates[0].Status)
	assert.Equal(t, model.PlatformAccountBindingStatusDeleteFailed, candidates[1].Status)
}
