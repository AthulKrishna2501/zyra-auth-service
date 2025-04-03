package grpc

import (
	"net"

	"github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/services"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/logger"
	"google.golang.org/grpc"
)

func StartgRPCServer(UserRepo repository.UserRepository, log logger.Logger, rabbitMQ *events.RabbitMq, logger logger.Logger) error {
	go func() {
		lis, err := net.Listen("tcp", ":5001")
		if err != nil {
			log.Error("Failed to listen on port 5001: %v", err)
			return
		}

		grpcServer := grpc.NewServer()
		authService := services.NewAuthService(UserRepo, rabbitMQ, logger)
		auth.RegisterAuthServiceServer(grpcServer, authService)

		log.Info("gRPC Server started on port 3001")
		if err := grpcServer.Serve(lis); err != nil {
			log.Error("Failed to serve gRPC: %v", err)
		}
	}()

	return nil
}
