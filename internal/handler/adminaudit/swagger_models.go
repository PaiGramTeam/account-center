package adminaudit

import serviceaudit "paigram/internal/service/audit"

// swagger:model adminAuditErrorResponse
type AdminAuditErrorResponse struct {
	Error struct {
		Code    string      `json:"code"`
		Message string      `json:"message"`
		Details interface{} `json:"details,omitempty"`
	} `json:"error"`
}

// swagger:response adminAuditErrorResponse
type swaggerAdminAuditErrorResponse struct {
	// in: body
	Body AdminAuditErrorResponse
}

// swagger:model adminAuditListData
type AdminAuditListData struct {
	Items    []serviceaudit.AuditEventView `json:"items"`
	Total    int64                         `json:"total"`
	Page     int                           `json:"page"`
	PageSize int                           `json:"page_size"`
}

// swagger:response adminAuditListResponse
type swaggerAdminAuditListResponse struct {
	// in: body
	Body struct {
		Code    int                `json:"code"`
		Data    AdminAuditListData `json:"data"`
		Message string             `json:"message"`
	}
}

// swagger:response adminAuditDetailResponse
type swaggerAdminAuditDetailResponse struct {
	// in: body
	Body struct {
		Code    int                         `json:"code"`
		Data    serviceaudit.AuditEventView `json:"data"`
		Message string                      `json:"message"`
	}
}
