package main

import (
	"net"

	"github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/database"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/services"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/logger"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

func main() {
	log := logger.NewLogrusLogger()
	configEnv, err := config.LoadConfig()
	if err != nil {
		log.Error("Error in config .env: %v", err)
		return
	}

	config.InitRedis()

	db := database.ConnectDatabase(configEnv)
	if db == nil {
		log.Error("Failed to connect to database")
		return
	}

	userRepo := repository.NewUserRepository(db)

	go func() {
		lis, err := net.Listen("tcp", ":5001")
		if err != nil {
			log.Error("Failed to listen on port 5001: %v", err)
			return
		}

		grpcServer := grpc.NewServer()
		authService := services.NewAuthService(userRepo)
		auth.RegisterAuthServiceServer(grpcServer, authService)

		log.Info("gRPC Server started on port 5001")
		if err := grpcServer.Serve(lis); err != nil {
			log.Error("Failed to serve gRPC: %v", err)
		}
	}()

	router := gin.Default()
	log.Info("HTTP Server started on port 5002")
	router.Run(":5002")
}
