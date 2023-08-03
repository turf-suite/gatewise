package v1

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"time"
	"strconv"
)
func NewLoginLimiter() func(*fiber.Ctx) error {
	return limiter.New(limiter.Config{
		Max: 10,
		Expiration: 5 * time.Minute,
		LimitReached: func(ctx *fiber.Ctx) error {
			retryTime := 300
			ctx.Set("Retry-After", strconv.Itoa(retryTime))
			return ctx.Status(fiber.StatusTooManyRequests).SendString(
				"Too many requests. Please try again later.")
	}})
}