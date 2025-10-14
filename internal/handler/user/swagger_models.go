//go:generate swagger generate spec -o ../../docs/swagger.json --scan-models

package user

import (
	"time"

	"paigram/internal/model"
)

// ErrorResponse represents a standard error payload for handlers.
//
// swagger:model errorResponse
type ErrorResponse struct {
	// Description of the error.
	// example: failed to list users
	Error string `json:"error"`
}

// swagger:response errorResponse
type swaggerErrorResponse struct {
	// in: body
	Body ErrorResponse
}

// swagger:model userEmail
type UserEmailPayload struct {
	Email      string     `json:"email"`
	IsPrimary  bool       `json:"is_primary"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// swagger:model userListItem
type UserListItem struct {
	ID               uint64           `json:"id"`
	Status           model.UserStatus `json:"status"`
	PrimaryLoginType model.LoginType  `json:"primary_login_type"`
	DisplayName      string           `json:"display_name"`
	PrimaryEmail     string           `json:"primary_email"`
	LastLoginAt      *time.Time       `json:"last_login_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

// swagger:model userListResponse
type UserListResponse struct {
	Data []UserListItem `json:"data"`
}

// swagger:response userListResponse
type swaggerUserListResponse struct {
	// in: body
	Body UserListResponse
}

// swagger:model userDetail
type UserDetail struct {
	ID               uint64             `json:"id"`
	Status           model.UserStatus   `json:"status"`
	PrimaryLoginType model.LoginType    `json:"primary_login_type"`
	DisplayName      string             `json:"display_name"`
	AvatarURL        string             `json:"avatar_url,omitempty"`
	Bio              string             `json:"bio,omitempty"`
	Locale           string             `json:"locale,omitempty"`
	PrimaryEmail     string             `json:"primary_email"`
	Emails           []UserEmailPayload `json:"emails"`
	LastLoginAt      *time.Time         `json:"last_login_at,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// swagger:model userDetailResponse
type UserDetailResponse struct {
	Data UserDetail `json:"data"`
}

// swagger:response userDetailResponse
type swaggerUserDetailResponse struct {
	// in: body
	Body UserDetailResponse
}

// swagger:parameters getUser
type getUserParams struct {
	// User ID.
	// in: path
	// required: true
	ID uint64 `json:"id"`
}
