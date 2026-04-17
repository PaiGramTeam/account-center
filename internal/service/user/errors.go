package user

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrRoleNotFound           = errors.New("role not found")
	ErrPrimaryRoleNotAssigned = errors.New("primary role must belong to user")
)
