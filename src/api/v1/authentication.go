package v1

import (
	"database/sql"
	"log"
	"time"
	"turf-auth/src/api"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var signingKey = []byte("MXoSfsFDFnjHdoaSmUbCaIqt5oTDvM-3sE6ckDcKqt-mn0yedPCbslI5xwP5mQJs-jVNVKRUawXTFFDhryW2wiPon6If9UsOm5X3Nggmqw67kjZNI4sL16zOTkmBWKWvuRExU6ZZgG9aIL6TS0oGZf0LiBMuJJA_-gWCbsEYRn5U4nI6eBAzkC24R9n9CzvDvYZnEuAFLzmMdRE7ZvC9jCKz23dQ5oAdLQrbfq3ECwiJzVLXF7tGcuYV49QFrlDi-yeT7W0MY53b09KgimaQNAWbEpnkl4RY43s3MtmAj_vU39PEGZRaXeJHv-_a9iXXdxB01VUw6qVQBcPaS0b5gQ")

func generateJWT(id string, issuer string) *jwt.Token {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer,
		"sub": id,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"aud": "Turf-Suite",
		"exp": now.AddDate(0, 0, 7).Unix(),
		"jti": uuid.New().String()})
}

func register(id string, user *User) error {
	userQuery := `
		INSERT INTO users (id, firstname, lastname, email, password)
		VALUES ($1, $2, $3, $4, $5)
	`
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12); if err != nil {
		return err
	}
	_, err = api.DB.Exec(
		userQuery,
		id,
		user.Firstname,
		user.Lastname,
		user.Email,
		hashedPassword)
	return err
}

func login(credentials *UserLogin) (string, error) {
	userData := api.DB.QueryRow("SELECT id, password FROM users WHERE email = $1", credentials.Email)
	var (
		id string
		password string
	)
	err := userData.Scan(&id, &password); if err != nil {
		return "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(credentials.Password)); if err != nil {
		return "", err
	}
	token := generateJWT(id, "Turf-Auth")
	signed, err := token.SignedString(signingKey); if err != nil {
		return "", err
	}
	return signed, nil
}

func RegistrationHandler(ctx *fiber.Ctx) error {
	var data User
	id := uuid.New().String()
	token := generateJWT(id, "Turf-Auth")
	signed, err := token.SignedString(signingKey); if err != nil {
		log.Fatal(err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token"})
	}
	err = ctx.BodyParser(&data); if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the user registration info"})
	}
	err = register(id, &data); if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register new user"})
	}
	cookie := new(fiber.Cookie)
	cookie.Name = "turf-suite"
	cookie.HTTPOnly = true
	cookie.Value = signed
	cookie.SameSite = fiber.CookieSameSiteLaxMode
	cookie.Expires = time.Now().Add(time.Hour * 24)
	cookie.Secure = true
	ctx.Cookie(cookie)
	return ctx.JSON(fiber.Map{"message": "Registration Successful!"})
}

func LoginHandler(ctx *fiber.Ctx) error {
	token := ctx.Cookies("turf-suite", ""); if token != "" {
		return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User already authenticated"})
	}
	var loginCredentials UserLogin
	err := ctx.BodyParser(&loginCredentials); if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse the login credentials body"})
	}
	signed, err := login(&loginCredentials); if err != nil {
		switch(err) {
			case bcrypt.ErrMismatchedHashAndPassword:
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "The Password Didn't match!"})
			case sql.ErrNoRows:
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "No email found!"})
			default:
				log.Fatal(err)
				return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Unknown login error occurred on the server"})
		}
	}
	cookie := new(fiber.Cookie)
	cookie.Name = "turf-suite"
	cookie.HTTPOnly = true
	cookie.Value = signed
	cookie.SameSite = fiber.CookieSameSiteLaxMode
	cookie.Expires = time.Now().Add(time.Hour * 24)
	cookie.Secure = true
	ctx.Cookie(cookie)
	return ctx.JSON(fiber.Map{"message": "Login Successful!"})
}

func LogOutHandler(ctx *fiber.Ctx) error {
	token := ctx.Cookies("turf-suite", ""); if token == "" {
		return ctx.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User is not authenticated, so they cannot log out!"})
	}
	ctx.Cookie(&fiber.Cookie{
		HTTPOnly: true,
		Name: "turf-suite",
		Value: "",
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure: true,
		Expires: time.Now().Add(time.Hour * 24)})
	return ctx.JSON(fiber.Map{"message": "Log Out Successful"})
}