package utils

import (
	"math/rand"
	"strconv"
	"time"
)

func GenerateOTP() string {
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	otp := rng.Intn(900000) + 100000
	otpStr := strconv.Itoa(otp)

	return otpStr

}
