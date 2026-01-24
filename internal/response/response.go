package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response 统一的响应结构体
type Response struct {
	Code    int         `json:"code"`    // HTTP状态码或业务状态码
	Data    interface{} `json:"data"`    // 响应数据
	Message string      `json:"message"` // 响应消息
}

// ErrorDetail represents detailed error information
type ErrorDetail struct {
	Code    string      `json:"code"`              // Error code for client-side handling
	Message string      `json:"message"`           // User-friendly error message
	Details interface{} `json:"details,omitempty"` // Optional additional error details
}

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	Total      int64 `json:"total"`       // Total number of records
	Page       int   `json:"page"`        // Current page number
	PageSize   int   `json:"page_size"`   // Number of records per page
	TotalPages int   `json:"total_pages"` // Total number of pages
}

// PaginatedResponse represents a paginated response
type PaginatedResponse struct {
	Data       interface{}     `json:"data"`       // Paginated data
	Pagination *PaginationMeta `json:"pagination"` // Pagination metadata
}

// Success 返回成功响应
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Data:    data,
		Message: "success",
	})
}

// SuccessWithMessage 返回带自定义消息的成功响应
func SuccessWithMessage(c *gin.Context, data interface{}, message string) {
	c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Data:    data,
		Message: message,
	})
}

// Created 返回创建成功响应
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Code:    http.StatusCreated,
		Data:    data,
		Message: "created successfully",
	})
}

// Error 返回错误响应
func Error(c *gin.Context, httpCode int, message string) {
	c.JSON(httpCode, Response{
		Code:    httpCode,
		Data:    nil,
		Message: message,
	})
}

// ErrorWithData 返回带数据的错误响应
func ErrorWithData(c *gin.Context, httpCode int, message string, data interface{}) {
	c.JSON(httpCode, Response{
		Code:    httpCode,
		Data:    data,
		Message: message,
	})
}

// ErrorWithCode 返回带错误代码的错误响应
func ErrorWithCode(c *gin.Context, httpCode int, errCode string, message string, details interface{}) {
	errorDetail := ErrorDetail{
		Code:    errCode,
		Message: message,
		Details: details,
	}
	c.JSON(httpCode, gin.H{
		"error": errorDetail,
	})
}

// BadRequestWithCode 返回 400 错误（带错误代码）
func BadRequestWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusBadRequest, errCode, message, details)
}

// UnauthorizedWithCode 返回 401 错误（带错误代码）
func UnauthorizedWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusUnauthorized, errCode, message, details)
}

// ForbiddenWithCode 返回 403 错误（带错误代码）
func ForbiddenWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusForbidden, errCode, message, details)
}

// NotFoundWithCode 返回 404 错误（带错误代码）
func NotFoundWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusNotFound, errCode, message, details)
}

// ConflictWithCode 返回 409 错误（带错误代码）
func ConflictWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusConflict, errCode, message, details)
}

// InternalServerErrorWithCode 返回 500 错误（带错误代码）
func InternalServerErrorWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusInternalServerError, errCode, message, details)
}

// TooManyRequestsWithCode 返回 429 错误（带错误代码）
func TooManyRequestsWithCode(c *gin.Context, errCode string, message string, details interface{}) {
	ErrorWithCode(c, http.StatusTooManyRequests, errCode, message, details)
}

// BadRequest 返回 400 错误
func BadRequest(c *gin.Context, message string) {
	Error(c, http.StatusBadRequest, message)
}

// Unauthorized 返回 401 错误
func Unauthorized(c *gin.Context, message string) {
	Error(c, http.StatusUnauthorized, message)
}

// Forbidden 返回 403 错误
func Forbidden(c *gin.Context, message string) {
	Error(c, http.StatusForbidden, message)
}

// NotFound 返回 404 错误
func NotFound(c *gin.Context, message string) {
	Error(c, http.StatusNotFound, message)
}

// Conflict 返回 409 错误
func Conflict(c *gin.Context, message string) {
	Error(c, http.StatusConflict, message)
}

// InternalServerError 返回 500 错误
func InternalServerError(c *gin.Context, message string) {
	Error(c, http.StatusInternalServerError, message)
}

// TooManyRequests 返回 429 错误
func TooManyRequests(c *gin.Context, message string) {
	Error(c, http.StatusTooManyRequests, message)
}

// NoContent 返回 204 无内容响应
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Custom 返回自定义响应
func Custom(c *gin.Context, httpCode int, code int, data interface{}, message string) {
	c.JSON(httpCode, Response{
		Code:    code,
		Data:    data,
		Message: message,
	})
}

// SuccessWithPagination 返回分页成功响应
func SuccessWithPagination(c *gin.Context, data interface{}, total int64, page, pageSize int) {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	paginatedData := PaginatedResponse{
		Data: data,
		Pagination: &PaginationMeta{
			Total:      total,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: totalPages,
		},
	}

	c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Data:    paginatedData,
		Message: "success",
	})
}

// NewPaginationMeta creates a new PaginationMeta instance
func NewPaginationMeta(total int64, page, pageSize int) *PaginationMeta {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return &PaginationMeta{
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}
