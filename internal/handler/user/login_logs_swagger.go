package user

// swagger:parameters getLoginLogs
type getLoginLogsParams struct {
	// in: path
	// required: true
	// minimum: 1
	ID uint64 `json:"id"`
	// in: query
	// description: Page number
	// minimum: 1
	// default: 1
	Page int `json:"page"`
	// in: query
	// description: Items per page
	// minimum: 1
	// maximum: 100
	// default: 20
	PageSize int `json:"page_size"`
	// in: query
	// description: Filter by status
	// enum: success,failed
	Status string `json:"status"`
	// in: query
	// description: Start date (YYYY-MM-DD)
	// example: 2024-01-01
	DateFrom string `json:"date_from"`
	// in: query
	// description: End date (YYYY-MM-DD)
	// example: 2024-01-31
	DateTo string `json:"date_to"`
}

// LoginLogEntry represents a login attempt record
// swagger:model LoginLogEntry
type LoginLogEntry struct {
	// Log entry ID
	// example: 12345
	ID uint64 `json:"id"`
	// User ID
	// example: 1001
	UserID uint64 `json:"user_id"`
	// Login type
	// example: email
	LoginType string `json:"login_type"`
	// IP address
	// example: 192.168.1.100
	IP string `json:"ip"`
	// User agent string
	// example: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
	UserAgent string `json:"user_agent"`
	// Device info
	// example: Chrome / Windows
	Device string `json:"device"`
	// Location (City, Country)
	// example: Beijing, China
	Location string `json:"location"`
	// Login status
	// example: success
	// enum: success,failed
	Status string `json:"status"`
	// Failure reason (only present when status is failed)
	// example: invalid_password
	FailureReason string `json:"failure_reason,omitempty"`
	// Creation timestamp
	// example: 2024-01-23T10:00:00Z
	CreatedAt string `json:"created_at"`
}

// PaginationInfo contains pagination metadata
// swagger:model PaginationInfo
type PaginationInfo struct {
	// Total number of records
	// example: 150
	Total int64 `json:"total"`
	// Current page number
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// example: 20
	PageSize int `json:"page_size"`
	// Total number of pages
	// example: 8
	TotalPages int `json:"total_pages"`
}

// swagger:model loginLogsResponse
type LoginLogsResponse struct {
	// in: body
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items      []LoginLogEntry `json:"items"`
		Pagination PaginationInfo  `json:"pagination"`
	} `json:"data"`
}

// swagger:response loginLogsResponse
type loginLogsResponseWrapper struct {
	// in: body
	Body LoginLogsResponse
}
