package services

import (
	"context"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	pb "github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/middleware"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/utils"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var redisClient = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "",
	DB:       0,
})

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	userRepo    repository.UserRepository
	redisClient *redis.Client
	rabbitMq    *events.RabbitMq
}

func NewAuthService(userRepo repository.UserRepository, rabbitMq *events.RabbitMq) *AuthService {
	return &AuthService{userRepo: userRepo, redisClient: redisClient, rabbitMq: rabbitMq}
}

func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	exists, _ := s.userRepo.FindUserByEmail(req.Email)
	if exists != nil {
		return nil, status.Error(codes.AlreadyExists, models.ErrUserAlreadyExists.Error())
	}

	userID := uuid.New()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	userDetails := &models.UserDetails{
		ID:        uuid.New(),
		UserID:    userID,
		FirstName: req.Name,
	}

	if err := s.userRepo.CreateUserDetails(userDetails); err != nil {
		return nil, err
	}

	newUser := &models.User{
		ID:        userID,
		UserID:    userID,
		Email:     req.Email,
		Password:  string(hashedPassword),
		Role:      req.Role,
		IsBlocked: false,
	}

	if err := s.userRepo.CreateUser(newUser); err != nil {
		return nil, err
	}

	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	otp := rng.Intn(900000) + 100000
	otpStr := strconv.Itoa(otp)

	hashedEmail := utils.HashSHA256(req.Email)
	hashedOTP := utils.HashSHA256(otpStr)

	err := s.redisClient.Set(context.Background(), hashedEmail, hashedOTP, 5*time.Minute).Err()
	if err != nil {
		return nil, status.Error(codes.Aborted, "Unable to store otp in redis")
	}

	err = s.rabbitMq.PublishOTP(req.Email, otpStr)
	if err != nil {
		log.Println("Failed to Publish OTP ", err)
	} else {
		log.Printf("OTP %s published for email %s", otpStr, req.Email)
	}

	return &pb.RegisterResponse{
		Status:  http.StatusCreated,
		Message: "User Signup Successfull",
	}, nil
}

func (s *AuthService) Verify(ctx context.Context, req *pb.VerifyOTPRequest) (*pb.VerifyOTPResponse, error) {
	storedOTP, err := s.redisClient.Get(context.Background(), req.Email).Result()
	if err == redis.Nil {
		return nil, status.Error(codes.InvalidArgument, "Cannot get OTP from redis")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "server error")
	}

	if storedOTP != req.Otp {
		return nil, status.Error(codes.Unauthenticated, models.ErrOTPExpiredORInvalid.Error())
	}

	s.redisClient.Del(context.Background(), req.Email)

	if err := s.userRepo.UpdateField(req.Email, "is_email_verified", true); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update fields")
	}

	return &pb.VerifyOTPResponse{
		Status:  http.StatusOK,
		Message: "OTP verified successfully",
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {

	user, err := s.userRepo.FindUserByEmail(req.Email)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidEmailOrPassword.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidEmailOrPassword.Error())
	}

	if user.Role != req.Role {
		return nil, status.Error(codes.Unauthenticated, "Invalid Role")
	}

	accessToken, refreshToken, err := middleware.GenerateTokens(user.ID.String(), user.Role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate tokens")
	}

	err = s.redisClient.Set(ctx, user.ID.String(), refreshToken, 7*24*time.Hour).Err()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to store refresh token")
	}

	return &pb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Status:       http.StatusOK,
		Message:      models.MsgLoginSuccessful,
	}, nil

}
