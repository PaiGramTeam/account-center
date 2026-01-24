// Package response contains swagger models for the response package.
// This file provides swagger documentation for types defined in response.go
//
//go:generate swagger generate spec -o ../../docs/swagger.json --scan-models
package response

// swagger:model standardResponse
// StandardResponse represents the standard success response format
// NOTE: This is swagger documentation for the Response type in response.go
type swaggerStandardResponse struct {
	// Response code
	// example: 200
	Code int `json:"code"`
	// Response message
	// example: success
	Message string `json:"message"`
	// Response data
	Data interface{} `json:"data"`
}

// swagger:response standardResponse
type standardResponseWrapper struct {
	// in: body
	Body swaggerStandardResponse
}

// swagger:model errorResponse
// ErrorResponse represents the standard error response format
type swaggerErrorResponse struct {
	Error swaggerErrorDetail `json:"error"`
}

// swagger:model errorDetail
// ErrorDetail contains structured error information
// NOTE: This is swagger documentation for the ErrorDetail type in response.go
type swaggerErrorDetail struct {
	// Error code for client-side handling and internationalization
	// example: INVALID_CREDENTIALS
	Code string `json:"code"`
	// User-friendly error message
	// example: Invalid email or password
	Message string `json:"message"`
	// Optional additional error details
	// example: {"field": "email", "reason": "Email not verified"}
	Details interface{} `json:"details,omitempty"`
}

// swagger:response errorResponse
type errorResponseWrapper struct {
	// in: body
	Body swaggerErrorResponse
}

// swagger:model paginationMeta
// PaginationMeta represents pagination metadata
// NOTE: This is swagger documentation for the PaginationMeta type in response.go
type swaggerPaginationMeta struct {
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

// swagger:model paginatedResponse
// PaginatedResponse represents a standard paginated success response
type swaggerPaginatedResponse struct {
	// Response code
	// example: 200
	Code int `json:"code"`
	// Response message
	// example: success
	Message string `json:"message"`
	// Paginated data wrapped in data field
	Data swaggerPaginatedData `json:"data"`
}

// swagger:model paginatedData
// PaginatedData represents the data section of a paginated response
type swaggerPaginatedData struct {
	// List of items
	Data interface{} `json:"data"`
	// Pagination metadata
	Pagination *swaggerPaginationMeta `json:"pagination"`
}

// swagger:response paginatedResponse
type paginatedResponseWrapper struct {
	// in: body
	Body swaggerPaginatedResponse
}

// Common query parameters for pagination
// swagger:parameters paginationParams
type PaginationParams struct {
	// Page number (starting from 1)
	// in: query
	// minimum: 1
	// default: 1
	// example: 1
	Page int `json:"page"`
	// Number of items per page
	// in: query
	// minimum: 1
	// maximum: 100
	// default: 20
	// example: 20
	PageSize int `json:"page_size"`
}
