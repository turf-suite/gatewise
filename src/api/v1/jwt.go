package v1

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gofiber/fiber/v2"
	"time"
	"log"
	"turf-auth/src/api"
)

type UserUnauthorized struct {
	Message string
}

func (e *UserUnauthorized) Error() string {
	return fmt.Sprintf("User not authorized to access resource: %s", e.Message)
}

func generateJWT(id string, issuer string, exp time.Time) *jwt.Token {
	now := time.Now()
	date := jwt.NewNumericDate(now)
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   id,
		IssuedAt:  date,
		NotBefore: date,
		Audience:  jwt.ClaimStrings{"Turf-Auth"},
		ExpiresAt: jwt.NewNumericDate(exp),
		ID:        uuid.New().String()})
}

func parseTokenClaims(token string) (jwt.RegisteredClaims, error) {
	var claims jwt.RegisteredClaims
	jwtToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return api.Secret.SigningKey, nil
	})
	if err != nil {
		return claims, err
	}
	if !jwtToken.Valid {
		return claims, &UserUnauthorized{Message: "when parsing claims"}
	}
	return claims, nil
}

func validateToken(ctx *fiber.Ctx, token string) (bool, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return api.Secret.SigningKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return jwtToken.Valid, err
	}
	return jwtToken.Valid, nil
}

func refreshToken(token string) (*jwt.Token, error) {
	claims, err := parseTokenClaims(token)
	if err != nil {
		return nil, err
	}
	iat, err := claims.GetIssuedAt()
	if err != nil {
		return nil, err
	}
	refreshTime := iat.Add(time.Hour * 24)
	if time.Now().After(refreshTime) {
		return generateJWT(claims.Subject, "Turf-Auth", claims.ExpiresAt.Time), nil
	}
	return nil, nil
}

func createTokenCookie(token *jwt.Token) *fiber.Cookie {
	signed, err := token.SignedString(api.Secret.SigningKey)
	if err != nil {
		log.Fatal(err)
	}
	expTime, err := token.Claims.GetExpirationTime()
	if err != nil {
		log.Fatal(err)
	}
	cookie := new(fiber.Cookie)
	cookie.Name = authCookieName
	cookie.HTTPOnly = true
	cookie.Value = signed
	cookie.SameSite = fiber.CookieSameSiteLaxMode
	cookie.Expires = expTime.Time
	cookie.Secure = useHTTPS
	return cookie
}
