package user

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"paigram/internal/middleware"
	"paigram/internal/model"
	"paigram/internal/response"
)

// RegisterLoginLogRoutes registers login log routes
func (h *Handler) RegisterLoginLogRoutes(rg *gin.RouterGroup) {
	rg.GET("/:id/login-logs", middleware.SelfOrCasbinPermission(), h.GetLoginLogs)
}

// GetLoginLogs returns user's login history with pagination
//
// @Summary Get user login logs
// @Description Retrieves login history for a specific user with pagination support
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param status query string false "Filter by status" enum(success,failed)
// @Param date_from query string false "Start date (YYYY-MM-DD)"
// @Param date_to query string false "End date (YYYY-MM-DD)"
// @Success 200 {object} response.PaginatedResponse
// @Failure 400 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /api/v1/users/{id}/login-logs [get]
func (h *Handler) GetLoginLogs(c *gin.Context) {
	userID, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil {
		response.BadRequestWithCode(c, "INVALID_USER_ID", "invalid user id", nil)
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Build query
	query := h.db.Model(&model.LoginLog{}).Where("user_id = ?", userID)

	// Apply filters
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}

	if dateFrom := c.Query("date_from"); dateFrom != "" {
		if t, err := time.Parse("2006-01-02", dateFrom); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}

	if dateTo := c.Query("date_to"); dateTo != "" {
		if t, err := time.Parse("2006-01-02", dateTo); err == nil {
			// Add 1 day to include the entire end date
			query = query.Where("created_at < ?", t.AddDate(0, 0, 1))
		}
	}

	// Count total records
	var total int64
	if err := query.Count(&total).Error; err != nil {
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to count login logs", nil)
		return
	}

	// Calculate pagination
	offset := (page - 1) * pageSize
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Fetch logs
	var logs []model.LoginLog
	if err := query.
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&logs).Error; err != nil {
		response.InternalServerErrorWithCode(c, "DB_ERROR", "failed to fetch login logs", nil)
		return
	}

	// Format response
	logList := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		logItem := gin.H{
			"id":         log.ID,
			"user_id":    log.UserID,
			"login_type": log.LoginType,
			"ip":         log.IP,
			"user_agent": log.UserAgent,
			"device":     log.Device,
			"location":   log.Location,
			"status":     log.Status,
			"created_at": log.CreatedAt,
		}

		// Include failure reason only if status is failed
		if log.Status == "failed" && log.FailureReason != "" {
			logItem["failure_reason"] = log.FailureReason
		}

		logList = append(logList, logItem)
	}

	response.Success(c, gin.H{
		"data": logList,
		"pagination": gin.H{
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"total_pages": totalPages,
		},
	})
}

// LogLoginAttempt logs a login attempt (to be called from auth handler)
func LogLoginAttempt(db *gorm.DB, userID uint64, loginType model.LoginType, success bool, ip, userAgent, failureReason string) error {
	log := model.LoginLog{
		UserID:        userID,
		LoginType:     loginType,
		IP:            ip,
		UserAgent:     userAgent,
		Device:        parseDeviceFromUserAgent(userAgent),
		Location:      "", // Could be populated using IP geolocation service
		Status:        "success",
		FailureReason: "",
		CreatedAt:     time.Now(),
	}

	if !success {
		log.Status = "failed"
		log.FailureReason = failureReason
	}

	return db.Create(&log).Error
}

// Helper function to extract device info from user agent
func parseDeviceFromUserAgent(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Detect OS
	os := "Unknown OS"
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "mac"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		os = "iOS"
	}

	// Detect browser
	browser := "Unknown Browser"
	switch {
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		browser = "Safari"
	case strings.Contains(ua, "edge"):
		browser = "Edge"
	case strings.Contains(ua, "opera"):
		browser = "Opera"
	}

	return browser + " / " + os
}
