package interceptor

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"paigram/internal/grpc/service"
)

// AuthInterceptor provides authentication for gRPC calls
type AuthInterceptor struct {
	botAuthService *service.BotAuthService
	publicMethods  map[string]bool
}

// NewAuthInterceptor creates a new auth interceptor
func NewAuthInterceptor(db *gorm.DB) *AuthInterceptor {
	return &AuthInterceptor{
		botAuthService: service.NewBotAuthService(db),
		publicMethods: map[string]bool{
			"/paigram.v1.BotAuthService/RegisterBot":     true,
			"/paigram.v1.BotAuthService/BotLogin":        true,
			"/paigram.v1.BotAuthService/RefreshBotToken": true,
		},
	}
}

// Unary returns a server interceptor function to authenticate and authorize unary RPC
func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract token from metadata
		token, err := i.extractToken(ctx)
		if err != nil {
			return nil, err
		}

		// Validate token
		resp, err := i.botAuthService.ValidateBotToken(ctx, &service.ValidateBotTokenRequest{
			AccessToken: token,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to validate token")
		}
		if !resp.Valid {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token")
		}

		// Add bot info to context
		ctx = context.WithValue(ctx, "bot", resp.Bot)
		ctx = context.WithValue(ctx, "scopes", resp.Scopes)

		// Continue with the handler
		return handler(ctx, req)
	}
}

// Stream returns a server interceptor function to authenticate and authorize stream RPC
func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip auth for public methods
		if i.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Extract token from metadata
		token, err := i.extractToken(ss.Context())
		if err != nil {
			return err
		}

		// Validate token
		resp, err := i.botAuthService.ValidateBotToken(ss.Context(), &service.ValidateBotTokenRequest{
			AccessToken: token,
		})
		if err != nil {
			return status.Errorf(codes.Internal, "failed to validate token")
		}
		if !resp.Valid {
			return status.Errorf(codes.Unauthenticated, "invalid token")
		}

		// Add bot info to context
		ctx := context.WithValue(ss.Context(), "bot", resp.Bot)
		ctx = context.WithValue(ctx, "scopes", resp.Scopes)

		// Create wrapped stream with new context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		// Continue with the handler
		return handler(srv, wrappedStream)
	}
}

// extractToken extracts the bearer token from the context metadata
func (i *AuthInterceptor) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	authorization := md.Get("authorization")
	if len(authorization) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	// Extract bearer token
	parts := strings.SplitN(authorization[0], " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", status.Errorf(codes.Unauthenticated, "invalid authorization header format")
	}

	return parts[1], nil
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// GetBotFromContext retrieves bot info from context
func GetBotFromContext(ctx context.Context) (*service.Bot, bool) {
	bot, ok := ctx.Value("bot").(*service.Bot)
	return bot, ok
}

// GetScopesFromContext retrieves scopes from context
func GetScopesFromContext(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value("scopes").([]string)
	return scopes, ok
}

// CheckScope checks if the context has a specific scope
func CheckScope(ctx context.Context, requiredScope string) bool {
	scopes, ok := GetScopesFromContext(ctx)
	if !ok {
		return false
	}

	for _, scope := range scopes {
		if scope == requiredScope || scope == "admin.all" {
			return true
		}
	}

	return false
}
