package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"paigram/internal/model"
	serviceplatform "paigram/internal/service/platform"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

const (
	TypePlatformBindingReconcile        = "platform_binding:reconcile"
	TypePlatformBindingProjectionRepair = "platform_binding:projection_repair"
	platformBindingProjectionMaxAge     = 24 * time.Hour
)

type platformBindingTaskPayload struct {
	BindingID uint64 `json:"binding_id,omitempty"`
}

type platformBindingRepairCandidate struct {
	BindingID uint64
	Status    model.PlatformAccountBindingStatus
}

type platformBindingRepairScanner interface {
	ListCandidates(staleBefore time.Time) ([]platformBindingRepairCandidate, error)
}

type asynqEnqueuer interface {
	Enqueue(task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
}

type platformBindingProjectionRepairer interface {
	RepairProjection(ctx context.Context, bindingID uint64) (*model.PlatformAccountBinding, error)
}

type platformBindingReconcileScanner struct {
	db *gorm.DB
}

func NewPlatformBindingReconcileTask() (*asynq.Task, error) {
	return newPlatformBindingTask(TypePlatformBindingReconcile, 0)
}

func NewPlatformBindingProjectionRepairTask(bindingID uint64) (*asynq.Task, error) {
	return newPlatformBindingTask(TypePlatformBindingProjectionRepair, bindingID)
}

func newPlatformBindingTask(taskType string, bindingID uint64) (*asynq.Task, error) {
	payload, err := json.Marshal(platformBindingTaskPayload{BindingID: bindingID})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(taskType, payload, asynq.MaxRetry(5), asynq.Timeout(2*time.Minute)), nil
}

func NewPlatformBindingReconcileHandler(db *gorm.DB, enqueuer asynqEnqueuer) *PlatformBindingReconcileHandler {
	return &PlatformBindingReconcileHandler{scanner: &platformBindingReconcileScanner{db: db}, enqueuer: enqueuer}
}

func NewPlatformBindingReconcileHandlerWithScanner(scanner platformBindingRepairScanner, enqueuer asynqEnqueuer) *PlatformBindingReconcileHandler {
	return &PlatformBindingReconcileHandler{scanner: scanner, enqueuer: enqueuer}
}

type PlatformBindingReconcileHandler struct {
	scanner  platformBindingRepairScanner
	enqueuer asynqEnqueuer
}

func (h *PlatformBindingReconcileHandler) ProcessTask(_ context.Context, task *asynq.Task) error {
	if _, err := decodePlatformBindingTaskPayload(task); err != nil {
		return err
	}
	staleBefore := time.Now().UTC().Add(-platformBindingProjectionMaxAge)
	candidates, err := h.scanner.ListCandidates(staleBefore)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		var repairTask *asynq.Task
		if candidate.Status == model.PlatformAccountBindingStatusDeleteFailed {
			repairTask, err = NewPlatformBindingDeleteRepairTask(candidate.BindingID)
		} else {
			repairTask, err = NewPlatformBindingProjectionRepairTask(candidate.BindingID)
		}
		if err != nil {
			return err
		}
		if _, err := h.enqueuer.Enqueue(repairTask); err != nil {
			return fmt.Errorf("enqueue reconcile task for binding %d: %w", candidate.BindingID, err)
		}
	}
	log.Printf("[PlatformBindingReconcile] queued %d repair task(s)", len(candidates))
	return nil
}

func (s *platformBindingReconcileScanner) ListCandidates(staleBefore time.Time) ([]platformBindingRepairCandidate, error) {
	var bindings []model.PlatformAccountBinding
	const runtimeStaleClause = "external_account_key <> '' AND external_account_key IS NOT NULL AND (last_synced_at IS NULL OR last_synced_at < ? OR last_validated_at IS NULL OR last_validated_at < ?)"
	const profileDriftClause = "external_account_key <> '' AND external_account_key IS NOT NULL AND EXISTS (SELECT 1 FROM platform_account_profiles WHERE platform_account_profiles.binding_id = platform_account_bindings.id AND (platform_account_profiles.source_updated_at IS NULL OR platform_account_profiles.source_updated_at < ?))"
	err := s.db.Model(&model.PlatformAccountBinding{}).
		Where("status = ?", model.PlatformAccountBindingStatusDeleteFailed).
		Or("status = ?", model.PlatformAccountBindingStatusRefreshRequired).
		Or(runtimeStaleClause, staleBefore, staleBefore).
		Or(profileDriftClause, staleBefore).
		Order("id ASC").
		Find(&bindings).Error
	if err != nil {
		return nil, err
	}
	candidates := make([]platformBindingRepairCandidate, 0, len(bindings))
	for _, binding := range bindings {
		candidates = append(candidates, platformBindingRepairCandidate{BindingID: binding.ID, Status: binding.Status})
	}
	return candidates, nil
}

type PlatformBindingProjectionRepairHandler struct {
	repairer platformBindingProjectionRepairer
}

func NewPlatformBindingProjectionRepairHandler(db *gorm.DB, platformService *serviceplatform.PlatformService) *PlatformBindingProjectionRepairHandler {
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	return &PlatformBindingProjectionRepairHandler{repairer: serviceplatformbinding.NewRuntimeSummaryService(platformService, bindingService, profileService)}
}

func NewPlatformBindingProjectionRepairHandlerWithRepairer(repairer platformBindingProjectionRepairer) *PlatformBindingProjectionRepairHandler {
	return &PlatformBindingProjectionRepairHandler{repairer: repairer}
}

func (h *PlatformBindingProjectionRepairHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	payload, err := decodePlatformBindingTaskPayload(task)
	if err != nil {
		return err
	}
	_, err = h.repairer.RepairProjection(ctx, payload.BindingID)
	return err
}

func decodePlatformBindingTaskPayload(task *asynq.Task) (platformBindingTaskPayload, error) {
	var payload platformBindingTaskPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return payload, fmt.Errorf("unmarshal payload: %w", err)
	}
	return payload, nil
}
