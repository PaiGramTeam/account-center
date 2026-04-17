package platform

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type RuntimeState string

const (
	RuntimeStateHealthy       RuntimeState = "healthy"
	RuntimeStateUnreachable   RuntimeState = "unreachable"
	RuntimeStateUnknown       RuntimeState = "unknown"
	RuntimeStateDisabled      RuntimeState = "disabled"
	RuntimeStateMisconfigured RuntimeState = "misconfigured"
)

type runtimeProbeResult struct {
	State     RuntimeState
	CheckedAt time.Time
	Error     string
}

type platformHealthChecker interface {
	Check(ctx context.Context, endpoint string) runtimeProbeResult
}

type grpcHealthChecker struct {
	timeout time.Duration
}

func newGRPCHealthChecker(timeout time.Duration) *grpcHealthChecker {
	return &grpcHealthChecker{timeout: timeout}
}

func (c *grpcHealthChecker) Check(ctx context.Context, endpoint string) runtimeProbeResult {
	checkedAt := time.Now().UTC()
	if ctx == nil {
		ctx = context.Background()
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, c.timeout)
	defer dialCancel()

	conn, err := grpc.DialContext(dialCtx, endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return runtimeProbeResult{
			State:     RuntimeStateUnreachable,
			CheckedAt: checkedAt,
			Error:     err.Error(),
		}
	}
	defer func() {
		_ = conn.Close()
	}()

	checkCtx, checkCancel := context.WithTimeout(ctx, c.timeout)
	defer checkCancel()

	resp, err := healthpb.NewHealthClient(conn).Check(checkCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return runtimeProbeResult{
			State:     RuntimeStateUnreachable,
			CheckedAt: checkedAt,
			Error:     err.Error(),
		}
	}

	state, resultErr := mapHealthStatus(resp.GetStatus())

	return runtimeProbeResult{
		State:     state,
		CheckedAt: checkedAt,
		Error:     resultErr,
	}
}

func mapHealthStatus(status healthpb.HealthCheckResponse_ServingStatus) (RuntimeState, string) {
	if status == healthpb.HealthCheckResponse_SERVING {
		return RuntimeStateHealthy, ""
	}

	return RuntimeStateUnknown, fmt.Sprintf("unexpected health status: %s", status)
}
