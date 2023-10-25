package main

import (
	"database/sql"
	"log"
	"turf-gatewise/api"
	v1 "turf-gatewise/api/v1"
	"turf-gatewise/handlers"
	"turf-gatewise/repositories"
	"turf-gatewise/security"
	"turf-gatewise/utils"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
)

func main() {
	App := fiber.New()
	DB, err := sql.Open("postgres", utils.LoadEnvVariable("POSTGRES_CONNECTION"))
	if err != nil {
		log.Fatalf("Error connecting to postgres database: %v", err)
	}
	Secrets, err := security.NewSecretManager(security.Provider(utils.LoadEnvVariable("SECRETS_PROVIDER")))
	if err != nil {
		log.Fatalf("Error occurred when starting secret manager: %v", err)
	}
	TokenSigner := &security.SigningKeyManager{Secrets: Secrets}
	UserRepo := repositories.UserRepository{Db: DB}
	defer DB.Close()
	// handler api groups
	AuthGroup := handlers.AuthenticationGroup{Signer: TokenSigner, Repo: &UserRepo}
	Api := App.Group("/api")

	// v1 endpoints
	apiV1 := Api.Group("/v1")
	user := apiV1.Group("/user")
	user.Post("/register", v1.RegistrationMiddleware, AuthGroup.NewRegistrationHandler())
	user.Post("/login", v1.NewLoginLimiter(), AuthGroup.NewLoginHandler())
	user.Post("/logout", v1.AuthorizationMiddleware, AuthGroup.NewLogoutHandler())
	user.Post("/delete", v1.AuthorizationMiddleware, AuthGroup.NewAccountDeleteHandler())
	user.Post("/verify/:code", v1.AuthorizationMiddleware, v1.VerifyHandler)
	log.Fatal(api.App.Listen(":3000"))

	// Run the token rotater
	go security.TokenSigner.RotateSigningKeys()
}
