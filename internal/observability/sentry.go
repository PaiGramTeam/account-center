package observability

import (
	"context"
	"fmt"
	"net/url"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	sentry "github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"paigram/internal/buildinfo"
	"paigram/internal/config"
)

var sentryEnabled atomic.Bool

// Init initializes the shared Sentry client when enabled.
func Init(cfg config.SentryConfig) error {
	if !cfg.Enabled || strings.TrimSpace(cfg.DSN) == "" {
		sentryEnabled.Store(false)
		return nil
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              strings.TrimSpace(cfg.DSN),
		Environment:      strings.TrimSpace(cfg.Environment),
		Release:          resolveRelease(cfg),
		Debug:            cfg.Debug,
		AttachStacktrace: cfg.AttachStacktrace,
		SampleRate:       cfg.SampleRate,
		EnableTracing:    cfg.TracesSampleRate > 0,
		TracesSampleRate: cfg.TracesSampleRate,
		BeforeSend:       beforeSend,
	})
	if err != nil {
		return fmt.Errorf("init sentry: %w", err)
	}

	sentryEnabled.Store(true)
	return nil
}

// Enabled reports whether Sentry event delivery is active.
func Enabled() bool {
	return sentryEnabled.Load()
}

// Flush waits for buffered events to be sent.
func Flush(cfg config.SentryConfig) bool {
	if !Enabled() {
		return true
	}
	return sentry.Flush(flushTimeout(cfg))
}

// CaptureException records an error with optional scoped enrichment.
func CaptureException(err error, configureScope func(*sentry.Scope)) *sentry.EventID {
	if !Enabled() || err == nil {
		return nil
	}

	hub := sentry.CurrentHub()
	if hub == nil {
		return nil
	}

	var eventID *sentry.EventID
	hub.WithScope(func(scope *sentry.Scope) {
		if configureScope != nil {
			configureScope(scope)
		}
		eventID = hub.CaptureException(err)
	})
	return eventID
}

// CaptureMessage records a message with optional scoped enrichment.
func CaptureMessage(message string, configureScope func(*sentry.Scope)) *sentry.EventID {
	if !Enabled() || strings.TrimSpace(message) == "" {
		return nil
	}

	hub := sentry.CurrentHub()
	if hub == nil {
		return nil
	}

	var eventID *sentry.EventID
	hub.WithScope(func(scope *sentry.Scope) {
		if configureScope != nil {
			configureScope(scope)
		}
		eventID = hub.CaptureMessage(message)
	})
	return eventID
}

// GinMiddleware returns the request-aware Sentry middleware.
func GinMiddleware(cfg config.SentryConfig) gin.HandlerFunc {
	if !Enabled() {
		return nil
	}

	return sentrygin.New(sentrygin.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         flushTimeout(cfg),
	})
}

// GinScopeMiddleware annotates request scope and captures gin context errors.
func GinScopeMiddleware() gin.HandlerFunc {
	if !Enabled() {
		return nil
	}

	return func(c *gin.Context) {
		hub := sentrygin.GetHubFromContext(c)
		if hub != nil {
			hub.Scope().SetTag("component", "http")
			if clientIP := strings.TrimSpace(c.ClientIP()); clientIP != "" {
				hub.Scope().SetTag("client_ip", clientIP)
			}
		}

		c.Next()

		if hub == nil || c.Writer.Status() < 500 || len(c.Errors) == 0 {
			return
		}

		route := c.FullPath()
		for _, ginErr := range c.Errors {
			if ginErr.Err == nil {
				continue
			}
			hub.WithScope(func(scope *sentry.Scope) {
				if route != "" {
					scope.SetTag("http.route", route)
				}
				scope.SetTag("component", "http")
				scope.SetExtra("http.status_code", c.Writer.Status())
				hub.CaptureException(ginErr.Err)
			})
		}
	}
}

// UnaryServerInterceptor captures gRPC panics and server-side failures.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		if !Enabled() {
			return handler(ctx, req)
		}

		defer func() {
			if recovered := recover(); recovered != nil {
				panicErr := fmt.Errorf("panic in %s: %v", info.FullMethod, recovered)
				CaptureException(panicErr, func(scope *sentry.Scope) {
					applyGRPCScope(scope, ctx, info.FullMethod)
					scope.SetTag("grpc.kind", "unary")
				})
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		resp, err = handler(ctx, req)
		if err != nil && shouldCaptureGRPCStatus(status.Code(err)) {
			CaptureException(err, func(scope *sentry.Scope) {
				applyGRPCScope(scope, ctx, info.FullMethod)
				scope.SetTag("grpc.kind", "unary")
				scope.SetExtra("grpc.code", status.Code(err).String())
			})
		}

		return resp, err
	}
}

// StreamServerInterceptor captures gRPC stream panics and server-side failures.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		if !Enabled() {
			return handler(srv, stream)
		}

		ctx := stream.Context()

		defer func() {
			if recovered := recover(); recovered != nil {
				panicErr := fmt.Errorf("panic in %s: %v", info.FullMethod, recovered)
				CaptureException(panicErr, func(scope *sentry.Scope) {
					applyGRPCScope(scope, ctx, info.FullMethod)
					scope.SetTag("grpc.kind", "stream")
				})
				err = status.Error(codes.Internal, "internal server error")
			}
		}()

		err = handler(srv, stream)
		if err != nil && shouldCaptureGRPCStatus(status.Code(err)) {
			CaptureException(err, func(scope *sentry.Scope) {
				applyGRPCScope(scope, ctx, info.FullMethod)
				scope.SetTag("grpc.kind", "stream")
				scope.SetExtra("grpc.code", status.Code(err).String())
			})
		}

		return err
	}
}

func beforeSend(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event == nil {
		return nil
	}

	if event.Request == nil {
		return event
	}

	if shouldIgnoreRequestURL(event.Request.URL) {
		return nil
	}

	if event.Request.Headers != nil {
		delete(event.Request.Headers, "Authorization")
		delete(event.Request.Headers, "Cookie")
		delete(event.Request.Headers, "X-Api-Key")
	}
	event.Request.Cookies = ""

	return event
}

func shouldIgnoreRequestURL(rawURL string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	path := strings.TrimSpace(parsedURL.Path)
	return path == "/healthz"
}

func flushTimeout(cfg config.SentryConfig) time.Duration {
	if cfg.FlushTimeout <= 0 {
		return 2 * time.Second
	}
	return time.Duration(cfg.FlushTimeout) * time.Second
}

func shouldCaptureGRPCStatus(code codes.Code) bool {
	switch code {
	case codes.Internal, codes.Unknown, codes.DataLoss, codes.Unavailable, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

func applyGRPCScope(scope *sentry.Scope, ctx context.Context, fullMethod string) {
	scope.SetTag("component", "grpc")
	scope.SetTag("grpc.method", fullMethod)

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if userAgent := firstMetadataValue(md, "user-agent"); userAgent != "" {
			scope.SetExtra("grpc.user_agent", userAgent)
		}
		if requestID := firstMetadataValue(md, "x-request-id"); requestID != "" {
			scope.SetTag("request_id", requestID)
		}
	}

	if peerInfo, ok := peer.FromContext(ctx); ok && peerInfo.Addr != nil {
		scope.SetTag("peer.address", peerInfo.Addr.String())
	}
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func resolveRelease(cfg config.SentryConfig) string {
	if release := buildinfo.Release(); release != "" {
		return release
	}
	if release := releaseFromBuildInfo(); release != "" {
		return release
	}
	return strings.TrimSpace(cfg.Release)
}

func releaseFromBuildInfo() string {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok || buildInfo == nil {
		return ""
	}

	modulePath := strings.TrimSpace(buildInfo.Main.Path)
	moduleVersion := strings.TrimSpace(buildInfo.Main.Version)
	if moduleVersion != "" && moduleVersion != "(devel)" {
		if modulePath == "" {
			return moduleVersion
		}
		return modulePath + "@" + moduleVersion
	}

	revision := buildSetting(buildInfo, "vcs.revision")
	if revision == "" {
		return ""
	}

	if len(revision) > 12 {
		revision = revision[:12]
	}

	if modulePath == "" {
		modulePath = "app"
	}

	if buildSetting(buildInfo, "vcs.modified") == "true" {
		return modulePath + "@" + revision + "-dirty"
	}

	return modulePath + "@" + revision
}

func buildSetting(buildInfo *debug.BuildInfo, key string) string {
	for _, setting := range buildInfo.Settings {
		if setting.Key == key {
			return strings.TrimSpace(setting.Value)
		}
	}
	return ""
}
