package services

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	pb "github.com/AthulKrishna2501/proto-repo/auth"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/events"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/middleware"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/utils"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	userRepo    repository.UserRepository
	redisClient *redis.Client
	rabbitMq    *events.RabbitMq
}

func NewAuthService(userRepo repository.UserRepository, rabbitMq *events.RabbitMq) *AuthService {
	return &AuthService{userRepo: userRepo, redisClient: config.RedisClient, rabbitMq: rabbitMq}
}

func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	exists, _ := s.userRepo.FindUserByEmail(req.Email)
	if exists != nil {
		return nil, status.Error(codes.AlreadyExists, models.ErrUserAlreadyExists.Error())
	}

	if req.Role != "vendor" && req.Role != "client" {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidRole.Error())
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

	return &pb.RegisterResponse{
		Status:  http.StatusCreated,
		Message: "User Signup Successfull",
	}, nil
}

func (s *AuthService) SendOTP(ctx context.Context, req *pb.OTPRequest) (*pb.OTPResponse, error) {
	_, err := s.userRepo.FindUserByEmail(req.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidEmail.Error())
	}

	limited, err := utils.IsOTPLimited(s.redisClient, req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "Server error while checking rate limit")
	}

	if limited {
		return nil, status.Error(codes.ResourceExhausted, "Too many OTP requests. Please wait a minute and try again.")
	}
	otpStr := utils.GenerateOTP()

	hashedEmail := utils.HashSHA256(req.Email)

	err = s.redisClient.Set(context.Background(), hashedEmail, otpStr, 5*time.Minute).Err()
	if err != nil {
		return nil, status.Error(codes.Internal, "Unable to store otp in redis")
	}

	err = s.rabbitMq.PublishOTP(req.Email, otpStr)
	if err != nil {
		log.Println("Failed to Publish OTP ", err)
	} else {
		log.Printf("OTP %s published for email %s", otpStr, req.Email)
	}

	return &pb.OTPResponse{
		Status:  http.StatusOK,
		Message: "OTP has been sent to your email. Please check your inbox.",
	}, nil
}

func (s *AuthService) Verify(ctx context.Context, req *pb.VerifyOTPRequest) (*pb.VerifyOTPResponse, error) {

	hashedEmail := utils.HashSHA256(req.Email)
	storedOTP, err := s.redisClient.Get(context.Background(), hashedEmail).Result()
	if err == redis.Nil {
		return nil, status.Error(codes.Unauthenticated, "OTP expired or invalid")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "server error")
	}

	if storedOTP != req.Otp {
		return nil, status.Error(codes.Unauthenticated, models.ErrOTPExpiredORInvalid.Error())
	}

	s.redisClient.Del(context.Background(), hashedEmail)

	if err := s.userRepo.UpdateField(req.Email, "is_email_verified", true); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update fields")
	}

	return &pb.VerifyOTPResponse{
		Status:  http.StatusOK,
		Message: "OTP verified successfully",
	}, nil
}

func (s *AuthService) ResendOTP(ctx context.Context, req *pb.ResendOTPRequest) (*pb.ResendOTPResponse, error) {
	user, err := s.userRepo.FindUserByEmail(req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot find user")
	}

	if user.IsEmailVerified {
		return nil, status.Error(codes.AlreadyExists, "User is already verified")
	}
	hashedEmail := utils.HashSHA256(req.Email)

	existingOTP, err := s.redisClient.Get(context.Background(), hashedEmail).Result()
	if err == nil && existingOTP != "" {
		return nil, status.Error(codes.FailedPrecondition, "Previous OTP is still valid, please wait for expiration")
	}

	otpStr := utils.GenerateOTP()

	err = s.redisClient.Set(context.Background(), hashedEmail, otpStr, 5*time.Minute).Err()
	if err != nil {
		return nil, status.Error(codes.Aborted, "Unable to store otp in redis")
	}

	err = s.rabbitMq.PublishOTP(req.Email, otpStr)
	if err != nil {
		log.Println("Failed to Publish OTP ", err)
	} else {
		log.Printf("OTP %s published for email %s", otpStr, req.Email)
	}

	return &pb.ResendOTPResponse{
		Status:  http.StatusOK,
		Message: "OTP send successfull",
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	adminEmail := os.Getenv("ADMIN_EMAIL")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if req.Email == adminEmail && req.Role == "admin" {
		if req.Password != adminPassword {
			return nil, status.Error(codes.Unauthenticated, "Invalid email or password")
		}

		accessToken, refreshToken, err := middleware.GenerateTokens("admin_id", "admin")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to generate tokens")
		}

		return &pb.LoginResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			Status:       http.StatusOK,
			Message:      models.MsgLoginSuccessful,
		}, nil
	}
	
	user, err := s.userRepo.FindUserByEmail(req.Email)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidEmailOrPassword.Error())
	}

	isBlocked, err := s.redisClient.SIsMember(ctx, "blocked_users", user.ID.String()).Result()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to check block status")
	}
	if isBlocked {
		return nil, status.Error(codes.PermissionDenied, "Your account has been blocked. Contact support.")
	}
	if !user.IsEmailVerified {
		return nil, status.Error(codes.Unauthenticated, "Please verify your email before logging in")
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

func (s *AuthService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	tokenString := req.AccessToken

	token, err := middleware.ValidateToken(tokenString, middleware.AccessTokenSecret)

	if err != nil {

		return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims")
	}

	expiryTime := int64(claims["exp"].(float64))

	err = middleware.BlacklistToken(tokenString, expiryTime, s.redisClient)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to blacklist token")
	}

	return &pb.LogoutResponse{
		Message: models.MsgLogoutSuccessful,
	}, nil

}
func (s *AuthService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	token, err := middleware.ValidateToken(req.RefreshToken, middleware.RefreshTokenSecret)
	if err != nil || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid refresh token")
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	userID := claims["user_id"].(string)

	storedToken, err := s.redisClient.Get(ctx, userID).Result()
	if err == redis.Nil || storedToken != req.RefreshToken {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired refresh token")
	}

	newAccessToken, _, err := middleware.GenerateTokens(userID, "user")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate new access token")
	}

	return &pb.RefreshTokenResponse{
		AccessToken: newAccessToken,
	}, nil
}
