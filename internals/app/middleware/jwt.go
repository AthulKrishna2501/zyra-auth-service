package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var AccessTokenSecret = []byte("your-access-secret-key")
var RefreshTokenSecret = []byte("your-refresh-secret-key")

func GenerateTokens(userID string, role string) (string, string, error) {
	accessClaims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(AccessTokenSecret)
	if err != nil {
		return "", "", err
	}

	refreshClaims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(RefreshTokenSecret)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

func ValidateToken(tokenString string, secretKey []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return secretKey, nil
	})
}

func BlacklistToken(tokenString string, expiryTime int64, redisClient *redis.Client) error {
	ctx := context.Background()

	duration := time.Until(time.Unix(expiryTime, 0))
	if duration <= 0 {
		duration = time.Minute
	}

	err := redisClient.Set(ctx, "blacklist:"+tokenString, "revoked", duration).Err()
	if err != nil {
		return err
	}

	fmt.Println("Token blacklisted successfully:", tokenString)
	return nil

}
