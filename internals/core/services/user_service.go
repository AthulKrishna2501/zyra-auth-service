package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
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
	"github.com/AthulKrishna2501/zyra-auth-service/internals/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	userRepo    repository.UserRepository
	redisClient *redis.Client
	rabbitMq    *events.RabbitMq
	Oauth       *oauth2.Config
	log         logger.Logger
}

func NewAuthService(userRepo repository.UserRepository, rabbitMq *events.RabbitMq, logger logger.Logger) *AuthService {
	return &AuthService{userRepo: userRepo, redisClient: config.RedisClient, rabbitMq: rabbitMq, log: logger}
}

func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	exists, _ := s.userRepo.FindUserByEmail(req.Email)
	if exists != nil {
		return nil, status.Error(codes.AlreadyExists, models.ErrUserAlreadyExists.Error())
	}

	if req.Role != "vendor" && req.Role != "client" {
		return nil, status.Error(codes.Unauthenticated, models.ErrInvalidRole.Error())
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	userID := uuid.New()

	userDetails := &models.UserDetails{
		UserID:    userID,
		FirstName: req.Name,
	}

	if err := s.userRepo.CreateUserDetails(userDetails); err != nil {
		return nil, err
	}

	newUser := &models.User{
		UserID:   userID,
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     req.Role,
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
		s.log.Error("Failed to Publish OTP: ", err)

	} else {
		s.log.Info("OTP %s published for email %s", otpStr, req.Email)
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

	if err := s.userRepo.UpdateField(req.Email, "status", "pending"); err != nil {
		return nil, status.Error(codes.Internal, "Failed to udpated fields")
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
		s.log.Error("Failed to Publish OTP ", err)
	} else {
		s.log.Info("OTP %s published for email %s", otpStr, req.Email)
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

	accessToken, refreshToken, err := middleware.GenerateTokens(user.UserID.String(), user.Role)
	s.log.Info("UserID in GenerateToken function :", user.UserID.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate tokens")
	}

	err = s.redisClient.Set(ctx, user.UserID.String(), refreshToken, 7*24*time.Hour).Err()
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

func (s *AuthService) GoogleLogin(ctx context.Context, req *pb.GoogleLoginRequest) (*pb.GoogleLoginResponse, error) {
	s.Oauth = &oauth2.Config{
		RedirectURL:  "http://localhost:3000/auth/callback",
		ClientID:     os.Getenv("OAUTH_ID"),
		ClientSecret: os.Getenv("OAUTH_SECRET"),
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	url := s.Oauth.AuthCodeURL("state", oauth2.AccessTypeOffline)

	return &pb.GoogleLoginResponse{
		Status: http.StatusOK,
		Url:    url,
	}, nil

}

func (s *AuthService) HandleGoogleCallback(c context.Context, req *pb.GoogleCallbackRequest) (*pb.GoogleCallbackResponse, error) {
	client := &http.Client{}

	if s.Oauth == nil {
		return nil, status.Error(codes.Internal, "OAuth config not initialized")
	}

	t, err := s.Oauth.Exchange(context.Background(), req.Code)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to exchange token")

	}

	httpReq, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get user info "+err.Error())
	}

	httpReq.Header.Set("Authorization", "Bearer "+t.AccessToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to fetch user info: "+err.Error())
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to read response")

	}

	var userInfo struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, status.Error(codes.Internal, "Failed to parse user info: "+err.Error())
	}

	user, err := s.userRepo.FindUserByEmail(userInfo.Email)
	if err != nil && err != sql.ErrNoRows {
		return nil, status.Error(codes.Internal, "Failed to check user: "+err.Error())
	}

	if err := s.userRepo.UpdateField(user.Email, "sso_provider", "Google"); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update field for SSO")
	}

	if user == nil {
		newUser := models.User{
			Email:       userInfo.Email,
			SSOProvider: "Google",
			SSOUserID:   userInfo.ID,
			Role:        "client",
		}
		if err := s.userRepo.CreateUser(&newUser); err != nil {
			return nil, status.Error(codes.Internal, "Failed to create user: "+err.Error())
		}
	}

	if err := s.userRepo.UpdateField(userInfo.Email, "sso_provider", "Google"); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update SSO field")
	}

	accessToken, refreshToken, err := middleware.GenerateTokens(user.ID.String(), user.Role)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate JWT Token")
	}

	return &pb.GoogleCallbackResponse{
		Message:      "User Login Successfull",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
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
