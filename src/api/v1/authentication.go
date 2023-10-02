package v1

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"turf-auth/src/api"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	authCookieName     string = "turf-auth"
	useHTTPS           bool   = false
	tokenExpTime       int    = 14
	verifyCodeHash     string = "verify-codes"
	sendVerifyEmailUrl string = ""
)

func RegistrationHandler(ctx *fiber.Ctx) error {
	var (
		data          User
		emailResponse EmailSentResponse
	)
	id := uuid.New().String()
	token := generateJWT(id, "Turf-Auth", time.Now().AddDate(0, 0, tokenExpTime))
	_, err := token.SignedString(api.Secret.SigningKey)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token"})
	}
	err = ctx.BodyParser(&data)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the user registration info"})
	}
	verificationCode := generateVerificationCode(6)
	emailPayload, err := json.Marshal(SendVerifyEmailPayload{
		Email: data.Email,
		Code:  verificationCode,
		Name:  fmt.Sprintf("%s %s", data.Firstname, data.Lastname)})
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to parse verification email request payload"})
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
			"status": "error"})
	}
	ctx.Cookie(createTokenCookie(token))
	err = api.Redis.HSet(ctx.Context(), verifyCodeHash, verificationCode).Err()
	if err != nil {
		return ctx.JSON(fiber.Map{
			"status":       "success",
			"email_status": "error"})
	}
	resp, err := http.Post(
		fmt.Sprintf("%s/%s", sendVerifyEmailUrl, verificationCode),
		"application/json",
		bytes.NewBuffer(emailPayload))
	if err != nil {
		return ctx.JSON(fiber.Map{
			"status":       "success",
			"email_status": "error"})
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&emailResponse)
	if err != nil {
		return ctx.JSON(fiber.Map{
			"status":       "success",
			"email_status": "unknown"})
	}
	return ctx.JSON(fiber.Map{
		"status":       "success",
		"email_status": emailResponse.Status})
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
		handleAuthenticationError(ctx, err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(loginCredentials.Password))
	if err != nil {
		handleAuthenticationError(ctx, err)
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
		return handleAuthenticationError(ctx, err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password))
	if err != nil {
		return handleAuthenticationError(ctx, err)
	}
	// TODO: add MFA logic to confirm that the user wants to delete the account before this query
	_, err = api.DB.Exec("DELETE FROM users WHERE email = $0", credentials.Email)
	if err != nil {
		return handleAuthenticationError(ctx, err)
	}
	ctx.ClearCookie(authCookieName)
	return ctx.JSON(fiber.Map{"message": "Successfully Deleted Account!"})
}
