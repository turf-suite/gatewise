package api

import (
	"context"
	"database/sql"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"log"
)

const vaultUrl string = "https://turf-dev-keyvault.vault.azure.net/"

var (
	App    *fiber.App
	DB     *sql.DB
	Redis  *redis.Client
	Secret *Secrets
)

type Secrets struct {
	DBConnection string
	GoogleOAuth  string
	SlackOAuth   string
	SigningKey   []byte
}

func obtainSecretValue(client *azsecrets.Client, secret string) string {
	obtained, err := client.GetSecret(context.TODO(), secret, "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}
	return *obtained.Value
}

func init() {
	Secret = &Secrets{}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	client, err := azsecrets.NewClient(vaultUrl, cred, nil)
	if err != nil {
		log.Fatal(err)
	}
	Redis = redis.NewClient(&redis.Options{
		Addr:     "40.76.217.42:6379",
		Password: "",
		DB:       0})
	Secret.DBConnection = obtainSecretValue(client, "postgres")
	Secret.GoogleOAuth = obtainSecretValue(client, "google-oauth")
	Secret.SigningKey = []byte(obtainSecretValue(client, "signing-key"))
	App = fiber.New()
	DB, err = sql.Open("postgres", Secret.DBConnection)
	if err != nil {
		log.Fatal(err)
	}
}
