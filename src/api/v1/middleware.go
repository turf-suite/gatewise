package v1

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"strconv"
	"time"
	"fmt"
	"turf-auth/src/api"
)

func NewTokenAuthMiddleware() fiber.Handler {
	return keyauth.New(keyauth.Config{
		KeyLookup: fmt.Sprintf("cookie:%s", authCookieName),
		Validator: validateToken,
	})
}

func NewLoginLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        10,
		Expiration: 5 * time.Minute,
		LimitReached: func(ctx *fiber.Ctx) error {
			retryTime := 300
			ctx.Set("Retry-After", strconv.Itoa(retryTime))
			return ctx.Status(fiber.StatusTooManyRequests).SendString(
				"Too many requests. Please try again later.")
		}})
}

func RegistrationMiddleware(ctx *fiber.Ctx) error {
	var (
		data User
		id int
	)
	ctx.BodyParser(&data)
	userData := api.DB.QueryRow("SELECT id, FROM users WHERE email = $1", data.Email)
	err := userData.Scan(&id)
	if err != nil {
		return ctx.Next()
	}
	// do not let the user register if there is a row with the email
	return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "That Email Has Already Been Registered!"})
}

func TokenRefreshMiddleware(ctx *fiber.Ctx) error {
	token := ctx.Cookies(authCookieName, "")
	jwtToken, err := refreshToken(token)
	if err != nil {
		return ctx.SendStatus(fiber.StatusUnauthorized)
	}
	if jwtToken == nil {
		return ctx.Next()
	}
	ctx.ClearCookie(authCookieName)
	ctx.Cookie(createTokenCookie(jwtToken))
	return ctx.Next()
} 