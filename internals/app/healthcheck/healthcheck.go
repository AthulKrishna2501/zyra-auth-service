package healthcheck

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	amqp "github.com/rabbitmq/amqp091-go"
	"gorm.io/gorm"
)

var rdb *redis.Client
var db *gorm.DB

type HealthCheckResponse struct {
	Status   string   `json:"status"`
	Services []string `json:"services"`
}

func checkPostgres() string {
	if err := db.Raw("SELECT 1").Error; err != nil {
		return "Postgres is not healthy"
	}
	return "Postgres is healthy"
}

func checkRedis() string {
	_, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		return "Redis is not healthy"
	}
	return "Redis is healthy"
}

func checkRabbitMQ() string {
	conn, err := amqp.Dial("amqp://zyra:password123@rabbitmq:5672/")
	if err != nil {
		return "RabbitMQ is not healthy"
	}
	defer conn.Close()
	return "RabbitMQ is healthy"
}

func HealthCheckHandler(c *gin.Context) {
	services := []string{
		checkPostgres(),
		checkRedis(),
		checkRabbitMQ(),
	}

	response := HealthCheckResponse{
		Status:   "Auth Service is healthy!",
		Services: services,
	}

	c.JSON(http.StatusOK, response)
}
