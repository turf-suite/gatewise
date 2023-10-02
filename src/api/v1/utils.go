package v1

import (
	"math/rand"
)

func generateVerificationCode(length int) string {
	digits := "0123456789"
	verificationCode := make([]byte, length)
	for i := 0; i < length; i++ {
		verificationCode[i] = digits[rand.Intn(len(digits))]
	}
	return string(verificationCode)
}