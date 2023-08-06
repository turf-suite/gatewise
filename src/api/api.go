package api

import (
	"context"
	"database/sql"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"log"
)

const vaultUrl string = "https://turf-dev-keyvault.vault.azure.net/"

var (
	App *fiber.App
	DB  *sql.DB
)

type Secrets struct {
	DBConnection string
	GoogleOAuth  string
	SlackOAuth   string
}

var secrets *Secrets

func init() {
	secrets = &Secrets{}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	client, err := azsecrets.NewClient(vaultUrl, cred, nil)
	if err != nil {
		log.Fatal(err)
	}
	postgresCred, err := client.GetSecret(context.TODO(), "postgres", "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}
	googleCred, err := client.GetSecret(context.TODO(), "google-oauth", "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}
	App = fiber.New()
	secrets.DBConnection = *postgresCred.Value
	secrets.GoogleOAuth = *googleCred.Value
	DB, err = sql.Open("postgres", secrets.DBConnection)
	if err != nil {
		log.Fatal(err)
	}
}
