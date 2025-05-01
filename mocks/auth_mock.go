package mocks

import (
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindUserByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) CreateUser(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) CreateUserDetails(userDetails *models.UserDetails) error {
	args := m.Called(userDetails)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateField(email, field string, value interface{}) error {
	args := m.Called(email, field, value)
	return args.Error(0)
}

func (m *MockUserRepository) FindUserByID(id string) (*models.User, error) {
	args := m.Called(id)
	return args.Get(0).(*models.User), args.Error(1)
}
