package tasks

import (
	"context"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	serviceplatform "paigram/internal/service/platform"
	serviceplatformbinding "paigram/internal/service/platformbinding"
)

const TypePlatformBindingDeleteRepair = "platform_binding:delete_repair"

type platformBindingDeleteRepairer interface {
	RepairDeleteFailedBinding(ctx context.Context, bindingID uint64) error
}

func NewPlatformBindingDeleteRepairTask(bindingID uint64) (*asynq.Task, error) {
	return newPlatformBindingTask(TypePlatformBindingDeleteRepair, bindingID)
}

type PlatformBindingDeleteRepairHandler struct {
	repairer platformBindingDeleteRepairer
}

func NewPlatformBindingDeleteRepairHandler(db *gorm.DB, platformService *serviceplatform.PlatformService) *PlatformBindingDeleteRepairHandler {
	bindingService := serviceplatformbinding.NewBindingService(db)
	profileService := serviceplatformbinding.NewProfileProjectionService(db)
	grantService := serviceplatformbinding.NewGrantService(db)
	orchestrationService := serviceplatformbinding.NewOrchestrationService(bindingService, platformService, serviceplatform.NewGRPCGenericCredentialGateway(nil), profileService, grantService)
	return &PlatformBindingDeleteRepairHandler{repairer: orchestrationService}
}

func NewPlatformBindingDeleteRepairHandlerWithRepairer(repairer platformBindingDeleteRepairer) *PlatformBindingDeleteRepairHandler {
	return &PlatformBindingDeleteRepairHandler{repairer: repairer}
}

func (h *PlatformBindingDeleteRepairHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {
	payload, err := decodePlatformBindingTaskPayload(task)
	if err != nil {
		return err
	}
	return h.repairer.RepairDeleteFailedBinding(ctx, payload.BindingID)
}
