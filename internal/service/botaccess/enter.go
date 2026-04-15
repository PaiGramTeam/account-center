package botaccess

import (
	"paigram/internal/config"

	"gorm.io/gorm"
)

// ServiceGroup aggregates bot access services.
type ServiceGroup struct {
	AccountRefService AccountRefService
	TicketService     TicketService
}

// NewServiceGroup creates the bot access service group.
func NewServiceGroup(db *gorm.DB, authCfg config.AuthConfig) (*ServiceGroup, error) {
	ticketService, err := NewTicketService(authCfg)
	if err != nil {
		return nil, err
	}

	return &ServiceGroup{
		AccountRefService: AccountRefService{db: db},
		TicketService:     *ticketService,
	}, nil
}
