package security

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	authCookieName       string        = "turf-auth"
	useHTTPS             bool          = false
	signingKeyLength     int           = 32
	signingKeyLifetime   time.Duration = 30 * 24 * time.Hour // token signing keys shall last 30 days
	accessTokenLifetime  time.Duration = 1 * time.Hour
	refreshTokenLifetime time.Duration = 14 * 24 * time.Hour
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

type SigningKeyManager struct {
	signingKey   []byte
	nextRotation time.Time
	secrets      SecretManager
}

func (secrets *SigningKeyManager) newSigningKey() {
	ctx := context.Background()
	randomBytes := make([]byte, signingKeyLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalf("Failed to generate random byte string for signing key %v", err)
	}
	secrets.signingKey = randomBytes
	secrets.secrets.Set(ctx, "signing-key", randomBytes)
}

func (signer *SigningKeyManager) IssueRefreshToken(id string) *jwt.Token {
	return generateJWT(id, "Turf-Auth", time.Now().Add(refreshTokenLifetime))
}

func (signer *SigningKeyManager) IssueAccessToken(id string) *jwt.Token {
	return generateJWT(id, "Turf-Auth", time.Now().Add(accessTokenLifetime))
}

func (signer *SigningKeyManager) ParseTokenClaims(token string) (jwt.RegisteredClaims, error) {
	var claims jwt.RegisteredClaims
	jwtToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return signer.signingKey, nil
	})
	if err != nil {
		return claims, err
	}
	if !jwtToken.Valid {
		return claims, &UserUnauthorized{Message: "when parsing claims"}
	}
	return claims, nil
}

func (signer *SigningKeyManager) IssueNewAccessToken(refreshToken string, accessToken string) (*jwt.Token, error) {
	now := time.Now()
	claims, err := signer.ParseTokenClaims(accessToken)
	if err != nil {
		return nil, err
	}
	accessIssuedAt, err := claims.GetIssuedAt()
	if err != nil {
		log.Fatal(err)
	}
	// the access token hasn't expired so new issuing is necessary
	if now.After(accessIssuedAt.Time) {
		return nil, nil
	}
	claims, err = signer.ParseTokenClaims(refreshToken)
	if err != nil {
		return nil, err
	}
	refreshExpTime, err := claims.GetExpirationTime()
	if err != nil {
		log.Fatal(err)
	}
	if refreshExpTime.Before(now) {
		return nil, &UserUnauthorized{}
	}
	accessExpTime := now.Add(accessTokenLifetime)
	return generateJWT(claims.Subject, "Turf-Auth", accessExpTime), nil
}

func (signer *SigningKeyManager) ValidateToken(ctx *fiber.Ctx, token string) (bool, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return signer.signingKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	if err != nil {
		return jwtToken.Valid, err
	}
	return jwtToken.Valid, nil
}

func (signer *SigningKeyManager) SignAndCreateCookie(token *jwt.Token, tokenCookieName string) *fiber.Cookie {
	signed, err := token.SignedString(signer.signingKey)
	if err != nil {
		log.Fatal(err) // shouldn't happen
	}
	expTime, err := token.Claims.GetExpirationTime()
	if err != nil {
		log.Fatal(err) // shouldn't happen
	}
	cookie := new(fiber.Cookie)
	cookie.Name = tokenCookieName
	cookie.HTTPOnly = true
	cookie.Value = signed
	cookie.SameSite = fiber.CookieSameSiteLaxMode
	cookie.Expires = expTime.Time
	cookie.Secure = useHTTPS
	return cookie
}

func (secrets *SigningKeyManager) RotateSigningKeys() {
	for {
		if time.Now().Before(secrets.nextRotation) {
			timeToNextRotation := secrets.nextRotation.Sub(time.Now())
			time.Sleep(timeToNextRotation)
		} else {
			secrets.newSigningKey()
			secrets.nextRotation = time.Now().Add(signingKeyLifetime)
			time.Sleep(signingKeyLifetime)
		}
	}
}

// add new function which creates instance and loads or generates signing key from key vault and then loads or sets the last key rotation date
func newSigningKeyManager(secrets SecretManager) {
	// test if there is a key in vault, if not, generate one from scratch and set the next rotation date to now with 30 days added
	// if there is a key in the vault, the database must have a next rotation time stored so set nextRotation to that stored value
}
