package me

import (
	"time"

	"paigram/internal/model"
	serviceme "paigram/internal/service/me"
)

// MeErrorResponse represents a structured error payload for /me endpoints.
// swagger:model meErrorResponse
type MeErrorResponse struct {
	Error struct {
		Code    string      `json:"code"`
		Message string      `json:"message"`
		Details interface{} `json:"details,omitempty"`
	} `json:"error"`
}

// swagger:response meErrorResponse
type swaggerMeErrorResponse struct {
	// in: body
	Body MeErrorResponse
}

// swagger:model meEnvelope
type meEnvelope struct {
	Code    int         `json:"code"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

// swagger:model meCurrentUser
type MeCurrentUser struct {
	ID           uint64                      `json:"id"`
	DisplayName  string                      `json:"display_name"`
	AvatarURL    string                      `json:"avatar_url,omitempty"`
	Bio          string                      `json:"bio,omitempty"`
	Locale       string                      `json:"locale,omitempty"`
	Status       model.UserStatus            `json:"status"`
	PrimaryEmail string                      `json:"primary_email,omitempty"`
	Roles        []string                    `json:"roles,omitempty"`
	Permissions  []string                    `json:"permissions,omitempty"`
	Emails       []serviceme.EmailView       `json:"emails"`
	LoginMethods []serviceme.LoginMethodView `json:"login_methods"`
	LastLoginAt  *time.Time                  `json:"last_login_at,omitempty"`
	CreatedAt    time.Time                   `json:"created_at"`
	UpdatedAt    time.Time                   `json:"updated_at"`
}

// swagger:model meDashboardSummary
type MeDashboardSummary = serviceme.DashboardSummaryView

// swagger:model meMessageOnly
type MeMessageOnly struct {
	Message string `json:"message"`
}

// swagger:model meVerifyEmailResult
type MeVerifyEmailResult struct {
	Message               string `json:"message"`
	VerificationExpiresAt string `json:"verification_expires_at"`
}

// swagger:model meBackupCodesResult
type MeBackupCodesResult struct {
	Message     string   `json:"message"`
	BackupCodes []string `json:"backup_codes"`
}

// swagger:response meCurrentUserResponse
type swaggerCurrentUserResponse struct {
	// in: body
	Body struct {
		Code    int           `json:"code"`
		Data    MeCurrentUser `json:"data"`
		Message string        `json:"message"`
	}
}

// swagger:response meDashboardSummaryResponse
type swaggerDashboardSummaryResponse struct {
	// in: body
	Body struct {
		Code    int                `json:"code"`
		Data    MeDashboardSummary `json:"data"`
		Message string             `json:"message"`
	}
}

// swagger:response meEmailsResponse
type swaggerEmailsResponse struct {
	// in: body
	Body struct {
		Code    int                   `json:"code"`
		Data    []serviceme.EmailView `json:"data"`
		Message string                `json:"message"`
	}
}

// swagger:response meCreatedEmailResponse
type swaggerCreatedEmailResponse struct {
	// in: body
	Body struct {
		Code    int                        `json:"code"`
		Data    serviceme.CreatedEmailView `json:"data"`
		Message string                     `json:"message"`
	}
}

// swagger:response meVerifyEmailResponse
type swaggerVerifyEmailResponse struct {
	// in: body
	Body struct {
		Code    int                 `json:"code"`
		Data    MeVerifyEmailResult `json:"data"`
		Message string              `json:"message"`
	}
}

// swagger:response meMessageResponse
type swaggerMessageResponse struct {
	// in: body
	Body struct {
		Code    int           `json:"code"`
		Data    MeMessageOnly `json:"data"`
		Message string        `json:"message"`
	}
}

// swagger:response meLoginMethodsResponse
type swaggerLoginMethodsResponse struct {
	// in: body
	Body struct {
		Code    int                         `json:"code"`
		Data    []serviceme.LoginMethodView `json:"data"`
		Message string                      `json:"message"`
	}
}

// swagger:response meSecurityOverviewResponse
type swaggerSecurityOverviewResponse struct {
	// in: body
	Body struct {
		Code    int                        `json:"code"`
		Data    serviceme.SecurityOverview `json:"data"`
		Message string                     `json:"message"`
	}
}

// swagger:response meTwoFactorSetupResponse
type swaggerTwoFactorSetupResponse struct {
	// in: body
	Body struct {
		Code    int                          `json:"code"`
		Data    serviceme.TwoFactorSetupView `json:"data"`
		Message string                       `json:"message"`
	}
}

// swagger:response meBackupCodesResponse
type swaggerBackupCodesResponse struct {
	// in: body
	Body struct {
		Code    int                 `json:"code"`
		Data    MeBackupCodesResult `json:"data"`
		Message string              `json:"message"`
	}
}

// swagger:response meSessionsResponse
type swaggerSessionsResponse struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Items      []serviceme.SessionView `json:"items"`
			Pagination struct {
				Total      int64 `json:"total"`
				Page       int   `json:"page"`
				PageSize   int   `json:"page_size"`
				TotalPages int   `json:"total_pages"`
			} `json:"pagination"`
		} `json:"data"`
	}
}

// swagger:response meActivityLogsResponse
type swaggerActivityLogsResponse struct {
	// in: body
	Body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Items      []serviceme.ActivityLogView `json:"items"`
			Pagination struct {
				Total      int64 `json:"total"`
				Page       int   `json:"page"`
				PageSize   int   `json:"page_size"`
				TotalPages int   `json:"total_pages"`
			} `json:"pagination"`
		} `json:"data"`
	}
}

// swagger:parameters createMeEmail
type createMeEmailParams struct {
	// Email create payload.
	// in: body
	// required: true
	Body struct {
		// example: alt@example.com
		Email string `json:"email"`
	} `json:"body"`
}

// swagger:parameters patchMe
type patchMeParams struct {
	// Current-user self-service profile update payload.
	// Only display_name, avatar_url, bio, and locale are accepted.
	// in: body
	// required: true
	Body struct {
		// example: Account Operator
		DisplayName *string `json:"display_name"`
		// example: https://example.com/avatar.png
		AvatarURL *string `json:"avatar_url"`
		// max length: 500
		Bio *string `json:"bio"`
		// example: zh_CN
		// max length: 10
		Locale *string `json:"locale"`
	} `json:"body"`
}

// swagger:parameters patchMePrimaryEmail deleteMeEmail verifyMeEmail
type meEmailIDParams struct {
	// Email ID.
	// in: path
	// required: true
	EmailID uint64 `json:"emailId"`
}

// swagger:parameters deleteMeLoginMethod patchMePrimaryLoginMethod
type meLoginMethodProviderParams struct {
	// Provider key.
	// in: path
	// required: true
	// example: github
	Provider string `json:"provider"`
}

// swagger:parameters updateMePassword
type updateMePasswordParams struct {
	// Password update payload.
	// in: body
	// required: true
	Body struct {
		OldPassword         string `json:"old_password"`
		NewPassword         string `json:"new_password"`
		RevokeOtherSessions bool   `json:"revoke_other_sessions"`
	} `json:"body"`
}

// swagger:parameters setupMeTwoFactor
type setupMeTwoFactorParams struct {
	// 2FA setup payload.
	// in: body
	// required: true
	Body struct {
		Password string `json:"password"`
	} `json:"body"`
}

// swagger:parameters confirmMeTwoFactor
type confirmMeTwoFactorParams struct {
	// 2FA confirm payload.
	// in: body
	// required: true
	Body struct {
		Code string `json:"code"`
	} `json:"body"`
}

// swagger:parameters disableMeTwoFactor
type disableMeTwoFactorParams struct {
	// 2FA disable payload.
	// in: body
	// required: true
	Body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	} `json:"body"`
}

// swagger:parameters regenerateMeBackupCodes
type regenerateMeBackupCodesParams struct {
	// Backup code regeneration payload.
	// in: body
	// required: true
	Body struct {
		Password string `json:"password"`
	} `json:"body"`
}

// swagger:parameters revokeMeSession
type revokeMeSessionParams struct {
	// Session ID.
	// in: path
	// required: true
	SessionID uint64 `json:"sessionId"`
}

// swagger:parameters listMeSessions
type listMeSessionsParams struct {
	// Page number.
	// in: query
	// default: 1
	Page int `json:"page"`
	// Items per page.
	// in: query
	// default: 20
	// maximum: 100
	PageSize int `json:"page_size"`
}

// swagger:parameters listMeActivityLogs
type listMeActivityLogsParams struct {
	// Page number.
	// in: query
	// default: 1
	Page int `json:"page"`
	// Items per page.
	// in: query
	// default: 20
	// maximum: 100
	PageSize int `json:"page_size"`
	// Optional activity action filter.
	// in: query
	// example: password_change
	ActionType string `json:"action_type"`
}
