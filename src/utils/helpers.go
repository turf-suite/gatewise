package utils

import (
	"log"
	"math/rand"
	"os"

	"github.com/joho/godotenv"
)

func GenerateVerificationCode(length int) string {
	digits := "0123456789"
	verificationCode := make([]byte, length)
	for i := 0; i < length; i++ {
		verificationCode[i] = digits[rand.Intn(len(digits))]
	}
	return string(verificationCode)
}

func LoadEnvVariable(variable string) string {
	value := os.Getenv(variable)
	if value == "" {
		err := godotenv.Load("../../../.env")
		if err != nil {
			log.Fatal(err)
		}
	}
	return os.Getenv(variable)
}
