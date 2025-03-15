package utils

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const otpRateLimitKey = "otp_limit:"

func IsOTPLimited(redisClient *redis.Client, email string) (bool, error) {
	ctx := context.Background()
	key := otpRateLimitKey + email

	count, err := redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return false, err
	}

	if count >= 3 {
		return true, nil
	}

	err = redisClient.Incr(ctx, key).Err()
	if err != nil {
		return false, err
	}

	if count == 0 {
		redisClient.Expire(ctx, key, time.Minute)
	}

	return false, nil
}
