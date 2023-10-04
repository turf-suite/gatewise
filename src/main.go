package main

import (
	"log"
	"turf-auth/src/api"
	v1 "turf-auth/src/api/v1"
)

func main() {
	defer api.DB.Close()
	Api := api.App.Group("/api")
	// v1 endpoints
	apiV1 := Api.Group("/v1")
	user := apiV1.Group("/user")
	user.Get("/auth", v1.AuthorizationMiddleware, v1.AuthHandler)
	user.Post("/register", v1.RegistrationMiddleware, v1.RegistrationHandler)
	user.Post("/login", v1.NewLoginLimiter(), v1.LoginHandler)
	user.Post("/logout", v1.AuthorizationMiddleware, v1.LogOutHandler)
	user.Post("/delete", v1.AuthorizationMiddleware, v1.AccountDeleteHandler)
	user.Post("/verify/:code", v1.AuthorizationMiddleware, v1.VerifyHandler)
	log.Fatal(api.App.Listen(":3000"))
}
