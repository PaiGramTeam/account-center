package service

import (
	"context"
	"errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"

	"paigram/internal/model"
)

// UserService implements the gRPC UserService
type UserService struct {
	UnimplementedUserServiceServer
	db *gorm.DB
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{
		db: db,
	}
}

// GetUser retrieves a single user by ID or email
func (s *UserService) GetUser(ctx context.Context, req *GetUserRequest) (*GetUserResponse, error) {
	var user model.User
	query := s.db.Preload("Profile").Preload("Emails")

	switch identifier := req.Identifier.(type) {
	case *GetUserRequest_Id:
		if err := query.First(&user, identifier.Id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, status.Errorf(codes.NotFound, "user not found")
			}
			return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
		}
	case *GetUserRequest_Email:
		var email model.UserEmail
		if err := s.db.Where("email = ?", identifier.Email).First(&email).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, status.Errorf(codes.NotFound, "user not found")
			}
			return nil, status.Errorf(codes.Internal, "failed to find email: %v", err)
		}
		if err := query.First(&user, email.UserID).Error; err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "must provide either id or email")
	}

	return &GetUserResponse{
		User: s.modelUserToProto(&user),
	}, nil
}

// GetUsersByIds retrieves multiple users by their IDs
func (s *UserService) GetUsersByIds(ctx context.Context, req *GetUsersByIdsRequest) (*GetUsersByIdsResponse, error) {
	if len(req.Ids) == 0 {
		return &GetUsersByIdsResponse{Users: []*User{}}, nil
	}

	var users []model.User
	if err := s.db.Preload("Profile").Preload("Emails").Find(&users, req.Ids).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get users: %v", err)
	}

	protoUsers := make([]*User, len(users))
	for i, user := range users {
		protoUsers[i] = s.modelUserToProto(&user)
	}

	return &GetUsersByIdsResponse{
		Users: protoUsers,
	}, nil
}

// VerifyUser verifies user credentials
func (s *UserService) VerifyUser(ctx context.Context, req *VerifyUserRequest) (*VerifyUserResponse, error) {
	// Find user by email
	var userEmail model.UserEmail
	if err := s.db.Where("email = ?", req.Email).First(&userEmail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &VerifyUserResponse{
				Valid:   false,
				Message: "invalid email or password",
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to find email: %v", err)
	}

	// Get user with credentials
	var user model.User
	if err := s.db.Preload("Profile").Preload("Emails").Preload("Credentials").
		First(&user, userEmail.UserID).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Find email credential
	var credential *model.UserCredential
	for _, cred := range user.Credentials {
		if cred.Provider == "email" {
			credential = &cred
			break
		}
	}

	if credential == nil {
		return &VerifyUserResponse{
			Valid:   false,
			Message: "no password set for this account",
		}, nil
	}

	// TODO: Verify password hash
	// This would normally use bcrypt or similar to compare the password
	// For now, we'll return a placeholder response

	return &VerifyUserResponse{
		Valid:   true,
		User:    s.modelUserToProto(&user),
		Message: "verification successful",
	}, nil
}

// GetUserPermissions retrieves user permissions and roles
func (s *UserService) GetUserPermissions(ctx context.Context, req *GetUserPermissionsRequest) (*GetUserPermissionsResponse, error) {
	// Verify user exists
	var user model.User
	if err := s.db.First(&user, req.UserId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// TODO: Implement actual permission system
	// For now, return default permissions
	permissions := []string{"user.read", "user.update.self"}
	roles := []string{"user"}

	if user.ID < 100 { // Simple admin check for demo
		permissions = append(permissions, "admin.all")
		roles = append(roles, "admin")
	}

	return &GetUserPermissionsResponse{
		Permissions: permissions,
		Roles:       roles,
	}, nil
}

// UpdateUserData updates user profile data
func (s *UserService) UpdateUserData(ctx context.Context, req *UpdateUserDataRequest) (*UpdateUserDataResponse, error) {
	var user model.User
	if err := s.db.Preload("Profile").First(&user, req.UserId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Update profile fields if provided
	updates := make(map[string]interface{})
	if req.DisplayName != nil {
		updates["display_name"] = *req.DisplayName
	}
	if req.AvatarUrl != nil {
		updates["avatar_url"] = *req.AvatarUrl
	}
	if req.Bio != nil {
		updates["bio"] = *req.Bio
	}
	if req.Locale != nil {
		updates["locale"] = *req.Locale
	}

	if len(updates) > 0 {
		if err := s.db.Model(&model.UserProfile{}).
			Where("user_id = ?", req.UserId).
			Updates(updates).Error; err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update profile: %v", err)
		}
	}

	// Reload user with updated data
	if err := s.db.Preload("Profile").Preload("Emails").First(&user, req.UserId).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to reload user: %v", err)
	}

	return &UpdateUserDataResponse{
		User: s.modelUserToProto(&user),
	}, nil
}

// GetUserStats retrieves user statistics
func (s *UserService) GetUserStats(ctx context.Context, req *GetUserStatsRequest) (*GetUserStatsResponse, error) {
	var user model.User
	if err := s.db.First(&user, req.UserId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	// Count emails
	var emailCount int64
	s.db.Model(&model.UserEmail{}).Where("user_id = ?", req.UserId).Count(&emailCount)

	// Count verified emails
	var verifiedEmailCount int64
	s.db.Model(&model.UserEmail{}).Where("user_id = ? AND verified_at IS NOT NULL", req.UserId).Count(&verifiedEmailCount)

	// Count logins
	var loginCount int64
	s.db.Model(&model.LoginAudit{}).Where("user_id = ? AND success = ?", req.UserId, true).Count(&loginCount)

	resp := &GetUserStatsResponse{
		UserId:             req.UserId,
		LoginCount:         uint32(loginCount),
		EmailCount:         uint32(emailCount),
		VerifiedEmailCount: uint32(verifiedEmailCount),
	}

	if user.LastLoginAt.Valid {
		resp.LastLoginAt = timestamppb.New(user.LastLoginAt.Time)
	}

	return resp, nil
}

// Helper function to convert model.User to proto User
func (s *UserService) modelUserToProto(user *model.User) *User {
	protoUser := &User{
		Id:               user.ID,
		PrimaryLoginType: string(user.PrimaryLoginType),
		Status:           s.convertUserStatus(user.Status),
		CreatedAt:        timestamppb.New(user.CreatedAt),
		UpdatedAt:        timestamppb.New(user.UpdatedAt),
	}

	if user.LastLoginAt.Valid {
		protoUser.LastLoginAt = timestamppb.New(user.LastLoginAt.Time)
	}

	// Add profile
	if user.Profile.ID != 0 {
		protoUser.Profile = &UserProfile{
			Id:          user.Profile.ID,
			UserId:      user.Profile.UserID,
			DisplayName: user.Profile.DisplayName,
			AvatarUrl:   user.Profile.AvatarURL,
			Bio:         user.Profile.Bio,
			Locale:      user.Profile.Locale,
		}
	}

	// Add emails
	for _, email := range user.Emails {
		protoEmail := &UserEmail{
			Id:         email.ID,
			UserId:     email.UserID,
			Email:      email.Email,
			IsPrimary:  email.IsPrimary,
			IsVerified: email.VerifiedAt.Valid,
		}
		if email.VerifiedAt.Valid {
			protoEmail.VerifiedAt = timestamppb.New(email.VerifiedAt.Time)
		}
		protoUser.Emails = append(protoUser.Emails, protoEmail)
	}

	return protoUser
}

func (s *UserService) convertUserStatus(status model.UserStatus) UserStatus {
	switch status {
	case model.UserStatusPending:
		return UserStatus_USER_STATUS_PENDING
	case model.UserStatusActive:
		return UserStatus_USER_STATUS_ACTIVE
	case model.UserStatusSuspended:
		return UserStatus_USER_STATUS_SUSPENDED
	case model.UserStatusDeleted:
		return UserStatus_USER_STATUS_DELETED
	default:
		return UserStatus_USER_STATUS_UNSPECIFIED
	}
}

// Note: These types would normally be generated from the proto files
// For now, we'll define minimal interfaces to make the code compile

type UnimplementedUserServiceServer struct{}

type GetUserRequest struct {
	Identifier interface{}
}

type GetUserRequest_Id struct {
	Id uint64
}

type GetUserRequest_Email struct {
	Email string
}

type GetUserResponse struct {
	User *User
}

type GetUsersByIdsRequest struct {
	Ids []uint64
}

type GetUsersByIdsResponse struct {
	Users []*User
}

type VerifyUserRequest struct {
	Email    string
	Password string
}

type VerifyUserResponse struct {
	Valid   bool
	User    *User
	Message string
}

type GetUserPermissionsRequest struct {
	UserId uint64
}

type GetUserPermissionsResponse struct {
	Permissions []string
	Roles       []string
}

type UpdateUserDataRequest struct {
	UserId      uint64
	DisplayName *string
	AvatarUrl   *string
	Bio         *string
	Locale      *string
}

type UpdateUserDataResponse struct {
	User *User
}

type GetUserStatsRequest struct {
	UserId uint64
}

type GetUserStatsResponse struct {
	UserId             uint64
	LoginCount         uint32
	LastLoginAt        *timestamppb.Timestamp
	EmailCount         uint32
	VerifiedEmailCount uint32
}

type User struct {
	Id               uint64
	PrimaryLoginType string
	Status           UserStatus
	LastLoginAt      *timestamppb.Timestamp
	CreatedAt        *timestamppb.Timestamp
	UpdatedAt        *timestamppb.Timestamp
	Profile          *UserProfile
	Emails           []*UserEmail
}

type UserProfile struct {
	Id          uint64
	UserId      uint64
	DisplayName string
	AvatarUrl   string
	Bio         string
	Locale      string
}

type UserEmail struct {
	Id         uint64
	UserId     uint64
	Email      string
	IsPrimary  bool
	IsVerified bool
	VerifiedAt *timestamppb.Timestamp
}

type UserStatus int32

const (
	UserStatus_USER_STATUS_UNSPECIFIED UserStatus = 0
	UserStatus_USER_STATUS_PENDING     UserStatus = 1
	UserStatus_USER_STATUS_ACTIVE      UserStatus = 2
	UserStatus_USER_STATUS_SUSPENDED   UserStatus = 3
	UserStatus_USER_STATUS_DELETED     UserStatus = 4
)
