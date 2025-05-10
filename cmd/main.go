package main

import (
	"time"

	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/grpc"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/database"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	log := logger.NewLogrusLogger()

	config.InitRedis()

	configEnv, err := config.LoadConfig()
	if err != nil {
		log.Error("Error in config .env: %v", err)
		return
	}

	rabbitMQ, err := events.NewRabbitMq(configEnv.RABBITMQ_URL)
	if err != nil {
		log.Error("Could not connect to RabbitMQ:", err)
	}

	db := database.ConnectDatabase(configEnv)
	if db == nil {
		log.Error("Failed to connect to database")
		return
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Failed to get raw SQL DB:", err)
	}

	go database.StartMonitoring(sqlDB, 10*time.Minute)

	userRepo := repository.NewUserRepository(db)

	err = grpc.StartgRPCServer(userRepo, log, rabbitMQ, log, configEnv)

	if err != nil {
		log.Error("Failed to start gRPC server", err)
		return
	}

	router := gin.Default()
	log.Info("HTTP Server started on port 5001")
	router.Run(":5001")

}
