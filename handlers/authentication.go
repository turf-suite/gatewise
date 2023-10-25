package handlers

import (
	"database/sql"
	"log"
	"turf-gatewise/models"
	"turf-gatewise/repositories"
	"turf-gatewise/security"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthenticationGroup struct {
	Repo   repositories.UserManager
	Signer *security.SigningKeyManager
}

func (group *AuthenticationGroup) NewRegistrationHandler() func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		var (
			data models.RegistrationPayload
		)
		id := uuid.New()
		err := ctx.BodyParser(&data)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Failed to parse the user registration info"})
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), 12)
		if err != nil {
			log.Fatal(err)
		}
		err = group.Repo.CreateNewUser(&models.User{
			Id:        id,
			FirstName: data.Firstname,
			LastName:  data.Lastname,
			Email:     data.Email,
			Password:  string(hashedPassword),
		})
		if err != nil {
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status": err})
		}
		group.issueTokens(id.String(), ctx)
		return ctx.JSON(fiber.Map{
			"status": "success"})
	}
}

func (group *AuthenticationGroup) NewLoginHandler() func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		token := ctx.Cookies("turf-auth", "")
		if token != "" {
			return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
				"message": "User already authenticated"})
		}
		var loginCredentials models.LoginPayload
		err := ctx.BodyParser(&loginCredentials)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Failed to parse the login credentials body"})
		}
		query, err := group.Repo.GetUserLoginDetails(loginCredentials.Email)
		if err != nil {
			return handleAuthenticationError(ctx, err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(query.Password), []byte(loginCredentials.Password))
		if err != nil {
			return handleAuthenticationError(ctx, err)
		}
		group.issueTokens(string(query.Id), ctx)
		return ctx.JSON(fiber.Map{"message": "Login Successful!"})
	}
}

func (group *AuthenticationGroup) NewLogoutHandler() func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		token := ctx.Cookies("turf-auth", "")
		if token == "" {
			return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
				"message": "User is not authenticated, so they cannot log out!"})
		}
		invalidateTokens(ctx)
		return ctx.JSON(fiber.Map{"message": "Log Out Successful"})
	}
}

func (group *AuthenticationGroup) NewAccountDeleteHandler() func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		var credentials models.LoginPayload
		err := ctx.BodyParser(&credentials)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Failed to parse the account credentials body"})
		}
		query, err := group.Repo.GetUserLoginDetails(credentials.Email)
		if err != nil {
			return handleAuthenticationError(ctx, err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(query.Password), []byte(credentials.Password))
		if err != nil {
			return handleAuthenticationError(ctx, err)
		}
		id, err := uuid.ParseBytes(query.Id)
		if err != nil {
			log.Fatalf("Error parsing the UUID in an account delete operation: %v", err)
		}
		group.Repo.DeleteUser(id)
		if err != nil {
			return handleAuthenticationError(ctx, err)
		}
		invalidateTokens(ctx)
		return ctx.JSON(fiber.Map{"message": "Successfully Deleted Account!"})
	}
}

func (group *AuthenticationGroup) issueTokens(userId string, ctx *fiber.Ctx) {
	refreshToken := group.Signer.IssueRefreshToken(userId)
	accessToken := group.Signer.IssueAccessToken(userId)
	ctx.Cookie(group.Signer.SignAndCreateCookie(accessToken, "turf-access"))
	ctx.Cookie(group.Signer.SignAndCreateCookie(refreshToken, "turf-auth"))
}

func handleAuthenticationError(ctx *fiber.Ctx, err error) error {
	switch err {
	case sql.ErrNoRows:
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No email found!"})
	case bcrypt.ErrMismatchedHashAndPassword:
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "The Password Didn't match!"})
	default:
		log.Println("Authentication error:", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unknown login error occurred on the server"})
	}
}

func invalidateTokens(ctx *fiber.Ctx) {
	ctx.ClearCookie("turf-access")
	ctx.ClearCookie("turf-auth")
}
