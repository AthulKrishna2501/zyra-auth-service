package repository

import (
	"errors"
	"fmt"

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
	CreateUserDetails(*models.UserDetails) error
	UpdateField(string, string, interface{}) error
}

func NewUserRepository(db *gorm.DB) *UserStorage {
	return &UserStorage{
		DB: db,
	}
}

func (repo *UserStorage) CreateUser(user *models.User) error {
	return repo.DB.Create(user).Error
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

func (repo *UserStorage) CreateUserDetails(user *models.UserDetails) error {
	if err := repo.DB.Create(user).Error; err != nil {
		return errors.New("failed to create user details:" + err.Error())

	}

	return nil
}

func (repo *UserStorage) UpdateField(email, field string, value interface{}) error {

	result := repo.DB.Model(&models.User{}).Where("email= ?", email).Update(field, value)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("no user found with id: %s", email)
	}

	return nil
}
