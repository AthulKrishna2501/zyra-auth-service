package repository

import (
	"errors"

	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"gorm.io/gorm"
)

type UserStorage struct {
	DB *gorm.DB
}

type UserRepository interface {
	FindUserByEmail(string) (*models.User, error)
	FindUserByID(string) (*models.User, error)
	CreateUser(*models.User) error
}

func NewUserRepository(db *gorm.DB) *UserStorage {
	return &UserStorage{
		DB: db,
	}
}

func (repo *UserStorage) CreateUser(user *models.User) error {
	if err := repo.DB.Create(user).Error; err != nil {
		return errors.New("failed to create user: " + err.Error())
	}
	return nil
}

func (repo *UserStorage) FindUser(field string, value interface{}) (*models.User, error) {
	var user models.User
	if err := repo.DB.Where(field+" = ?", value).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, errors.New("failed to find user: " + err.Error())
	}
	return &user, nil
}

func (repo *UserStorage) FindUserByEmail(email string) (*models.User, error) {
	return repo.FindUser("email", email)
}

func (repo *UserStorage) FindUserByID(userID string) (*models.User, error) {
	return repo.FindUser("id", userID)
}
