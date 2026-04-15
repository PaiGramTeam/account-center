package server

import (
	"fmt"
	"log"
	"net"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"

	"paigram/internal/config"
	"paigram/internal/grpc/interceptor"
	pb "paigram/internal/grpc/pb/v1"
	grpcservice "paigram/internal/grpc/service"
	"paigram/internal/observability"
	"paigram/internal/service/botaccess"
)

// GRPCServer represents the gRPC server
type GRPCServer struct {
	port            int
	db              *gorm.DB
	redisClient     *redis.Client
	cfg             *config.Config
	server          *grpc.Server
	authInterceptor *interceptor.AuthInterceptor
}

// NewGRPCServer creates a new gRPC server
func NewGRPCServer(port int, db *gorm.DB, redisClient *redis.Client, cfg *config.Config) (*GRPCServer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("grpc config is required")
	}

	redisPrefix := "bot_token:"
	if cfg.Redis.Prefix != "" {
		redisPrefix = cfg.Redis.Prefix + redisPrefix
	}

	authInterceptor := interceptor.NewAuthInterceptor(db, redisClient, redisPrefix)

	// Create gRPC server with interceptors
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			observability.UnaryServerInterceptor(),
			authInterceptor.Unary(),
		),
		grpc.ChainStreamInterceptor(
			observability.StreamServerInterceptor(),
			authInterceptor.Stream(),
		),
	}

	server := grpc.NewServer(opts...)

	botAuthCore := grpcservice.NewBotAuthService(db, redisClient, redisPrefix)
	pb.RegisterBotAuthServiceServer(server, grpcservice.NewBotAuthServiceAdapter(botAuthCore))

	botAccessGroup, err := botaccess.NewServiceGroup(db, cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("init bot access services: %w", err)
	}
	pb.RegisterBotAccessServiceServer(server, grpcservice.NewBotAccessService(&botAccessGroup.AccountRefService, &botAccessGroup.TicketService))

	// Register reflection service for debugging
	reflection.Register(server)

	return &GRPCServer{
		port:            port,
		db:              db,
		redisClient:     redisClient,
		cfg:             cfg,
		server:          server,
		authInterceptor: authInterceptor,
	}, nil
}

// Start starts the gRPC server
func (s *GRPCServer) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Printf("gRPC server listening on port %d", s.port)

	// This is a blocking call
	if err := s.server.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

// Stop gracefully stops the gRPC server
func (s *GRPCServer) Stop() {
	log.Println("Stopping gRPC server...")
	s.server.GracefulStop()
}
