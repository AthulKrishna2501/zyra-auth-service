package services_test

import (
	"context"
	"testing"

	"github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/services"
	"github.com/AthulKrishna2501/zyra-auth-service/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockLogger struct{}

func (m *MockLogger) Info(message string, args ...interface{})  {}
func (m *MockLogger) Error(message string, args ...interface{}) {}
func (m *MockLogger) Debug(message string, args ...interface{}) {}
func (m *MockLogger) Warn(message string, args ...interface{})  {}

func TestAuthService_Register_Success(t *testing.T) {
	mockUserRepo := new(mocks.MockUserRepository)
	mockRabbitMQ := new(events.RabbitMq)
	mockLogger := &MockLogger{}
	authService := services.NewAuthService(mockUserRepo, mockRabbitMQ, mockLogger,config.Config{})

	req := &auth.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
		Role:     "vendor",
	}

	mockUserRepo.On("FindUserByEmail", req.Email).Return((*models.User)(nil), nil)
	mockUserRepo.On("CreateUserDetails", mock.Anything).Return(nil)
	mockUserRepo.On("CreateUser", mock.Anything).Return(nil)

	res, err := authService.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, int64(201), res.Status)
	assert.Equal(t, "User Signup Successfull", res.Message)

	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	mockUserRepo := new(mocks.MockUserRepository)
	mockRabbitMQ := new(events.RabbitMq)
	mockLogger := &MockLogger{}

	authService := services.NewAuthService(mockUserRepo, mockRabbitMQ, mockLogger,config.Config{})

	req := &auth.RegisterRequest{
		Email:    "existing@example.com",
		Password: "password123",
		Name:     "Existing User",
		Role:     "client",
	}

	mockUserRepo.On("FindUserByEmail", req.Email).Return(&models.User{}, nil)

	res, err := authService.Register(context.Background(), req)

	assert.Nil(t, res)
	assert.Error(t, err)
	assert.Equal(t, "rpc error: code = AlreadyExists desc = User already exists", err.Error())

	mockUserRepo.AssertExpectations(t)
}
