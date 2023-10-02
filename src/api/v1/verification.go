package v1

import (
	"context"
	"log"
	"turf-auth/src/api"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

func VerifyHandler(ctx *fiber.Ctx) error {
	code := ctx.Params("code")
	token := ctx.Cookies(authCookieName, "")
	if code == "" {
		return ctx.SendStatus(fiber.StatusBadRequest)
	}
	if token == "" {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	}
	claims, err := parseTokenClaims(token)
	if err != nil {
		switch err.(type) {
		case *UserUnauthorized:
			return ctx.SendStatus(fiber.StatusUnauthorized)
		default:
			return ctx.SendStatus(fiber.StatusInternalServerError)
		}
	}
	cachedCode, err := api.Redis.HGet(context.Background(), verifyCodeHash, claims.Subject).Result()
	if err != nil {
		if err == redis.Nil {
			return ctx.Status(fiber.StatusGone).JSON(fiber.Map{
				"message": "The verification code has expired"})
		} else {
			log.Fatal(err)
		}
	}
	if cachedCode != code {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "The verification code didn't match the stored code!"})
	}
	_, err = api.DB.Exec("UPDATE users SET verified = $1 WHERE id = $2", true, claims.Subject)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "An unknown error occurred when verifying the user's email"})
	}
	// TODO: change this to a redirect back to turf home page
	return ctx.JSON(fiber.Map{
		"message": "User Verified!"})
}
