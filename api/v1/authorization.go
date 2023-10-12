package v1

import (
	"github.com/gofiber/fiber/v2"
)

func AuthHandler(ctx *fiber.Ctx) error {
	return ctx.SendString("Authorization endpoint reached")
}