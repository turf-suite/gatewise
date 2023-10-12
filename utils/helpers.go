package utils

import (
	"log"
	"math/rand"
	"os"
	"path/filepath"

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
		ex, err := os.Executable()
		if err != nil {
			log.Fatalf("Error loading .env file environment variables: %v", err)
		}
		envPath := filepath.Join(filepath.Dir(ex), ".env")
		err = godotenv.Load(envPath)
		if err != nil {
			log.Fatal(err)
		}
	}
	return os.Getenv(variable)
}
