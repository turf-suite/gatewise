package main

import (
    "log"
    "turf-auth/src/api/v1"
    "turf-auth/src/api"
)

func main() {
    defer api.DB.Close()
    Api := api.App.Group("/api")
    // v1 endpoints
    apiV1 := Api.Group("/v1")
	user := apiV1.Group("/user")
	user.Get("/auth", v1.AuthHandler)
	user.Post("/register", v1.RegistrationHandler)
	user.Post("/login", v1.LoginHandler).Use(v1.NewLoginLimiter())
	user.Post("/logout", v1.LogOutHandler)
    log.Fatal(api.App.Listen(":3000"))
}