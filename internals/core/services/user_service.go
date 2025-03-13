package services

import (
	"context"
	"net/http"

	"github.com/AthulKrishna2501/proto-repo/auth"
	pb "github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	auth.UnimplementedAuthServiceServer
	userRepo repository.UserRepository
}

func NewAuthService(userRepo repository.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo}
}

func (s *AuthService) SignUp(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	exists, _ := s.userRepo.FindUserByEmail(req.Email)
	if exists != nil {
		return nil, models.ErrUserDoesNotExist
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	newUser := &models.User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		Role:      req.Role,
		IsBlocked: false,
	}

	if err := s.userRepo.CreateUser(newUser); err != nil {
		return nil, err
	}

	return &pb.RegisterResponse{
		Status:  http.StatusCreated,
		Message: "User Signup Successfull",
	}, nil
}

// func (s *AuthService) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
// 	user, err := s.userRepo.FindUserByEmail(req.Email)
// 	if err != nil {
// 		return nil, errors.New("user does not exist")
// 	}

// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
// 		return nil, errors.New("invalid password")
// 	}

// 	return &auth.LoginResponse{
// 		UserId:   user.ID.String(),
// 		Username: user.UserName,
// 		Email:    user.Email,
// 	}, nil
// }
