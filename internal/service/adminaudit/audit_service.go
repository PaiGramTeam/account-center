package adminaudit

import "context"

// AuditService serves admin audit queries.
type AuditService struct{}

// NewAuditService creates an audit service.
func NewAuditService() *AuditService {
	return &AuditService{}
}

// ListAuditLogs returns an empty audit list until audit behavior lands.
func (s *AuditService) ListAuditLogs(context.Context) []map[string]any {
	return []map[string]any{}
}
