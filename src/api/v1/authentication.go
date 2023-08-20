package v1

import (
	"database/sql"
	"log"
	"time"
	"turf-auth/src/api"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	authCookieName string = "turf-auth"
	useHTTPS       bool   = false
	tokenExpTime   int    = 14
)

func RegistrationHandler(ctx *fiber.Ctx) error {
	var data User
	id := uuid.New().String()
	token := generateJWT(id, "Turf-Auth", time.Now().AddDate(0, 0, tokenExpTime))
	_, err := token.SignedString(api.Secret.SigningKey)
	if err != nil {
		log.Fatal(err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token"})
	}
	err = ctx.BodyParser(&data)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the user registration info"})
	}
	userQuery := `
		INSERT INTO users (id, firstname, lastname, email, password)
		VALUES ($1, $2, $3, $4, $5)`
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), 12)
	if err != nil {
		log.Fatal(err)
	}
	_, err = api.DB.Exec(
		userQuery,
		id,
		data.Firstname,
		data.Lastname,
		data.Email,
		hashedPassword)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register new user"})
	}
	ctx.Cookie(createTokenCookie(token))
	return ctx.JSON(fiber.Map{"message": "Registration Successful!"})
}

func LoginHandler(ctx *fiber.Ctx) error {
	token := ctx.Cookies(authCookieName, "")
	if token != "" {
		return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User already authenticated"})
	}
	var loginCredentials UserLogin
	err := ctx.BodyParser(&loginCredentials)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the login credentials body"})
	}
	userData := api.DB.QueryRow("SELECT id, password FROM users WHERE email = $1", loginCredentials.Email)
	var (
		id       string
		password string
	)
	err = userData.Scan(&id, &password)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No email found!"})
		default:
			log.Fatal(err)
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Unknown login error occurred on the server"})
		}
	}
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(loginCredentials.Password))
	if err != nil {
		switch err {
		case bcrypt.ErrMismatchedHashAndPassword:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "The Password Didn't match!"})
		default:
			log.Fatal(err)
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Unknown login error occurred on the server"})
		}
	}
	jwtToken := generateJWT(id, "Turf-Auth", time.Now().AddDate(0, 0, tokenExpTime))
	ctx.Cookie(createTokenCookie(jwtToken))
	return ctx.JSON(fiber.Map{"message": "Login Successful!"})
}

func LogOutHandler(ctx *fiber.Ctx) error {
	token := ctx.Cookies(authCookieName, "")
	if token == "" {
		return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User is not authenticated, so they cannot log out!"})
	}
	ctx.ClearCookie()
	return ctx.JSON(fiber.Map{"message": "Log Out Successful"})
}

func AccountDeleteHandler(ctx *fiber.Ctx) error {
	var credentials UserLogin
	err := ctx.BodyParser(&credentials)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the account credentials body"})
	}
	row := api.DB.QueryRow("SELECT password FROM users WHERE email = $1", credentials.Email)
	var hashedPassword string
	err = row.Scan(&hashedPassword)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "No user found!"})
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "The entered password for the user is incorrect!"})
	}
	// TODO: add MFA logic to confirm that the user wants to delete the account before this query
	_, err = api.DB.Exec("DELETE FROM users WHERE email = $0", credentials.Email)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "An error occured when deleting the user account!"})
	}
	ctx.ClearCookie(authCookieName)
	return ctx.JSON(fiber.Map{"message": "Successfully Deleted Account!"})
}