package grpc

import (
	"net"

	"github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/services"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/logger"
	"google.golang.org/grpc"
)

func StartgRPCServer(UserRepo repository.UserRepository, log logger.Logger, rabbitMQ *events.RabbitMq, logger logger.Logger, config config.Config) error {

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Error("Failed to listen on port 50051: %v", err)
		return err
	}

	grpcServer := grpc.NewServer()
	authService := services.NewAuthService(UserRepo, rabbitMQ, logger, config)
	auth.RegisterAuthServiceServer(grpcServer, authService)

	log.Info("gRPC Server started on port 50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Error("Failed to serve gRPC: %v", err)
	}

	return nil
}
