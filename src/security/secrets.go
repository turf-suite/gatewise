package security

import (
	"context"
	"log"
	"time"
	"turf-auth/src/utils"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type SecretManager interface {
	Set(ctx context.Context, key string, val any) error
	Get(ctx context.Context, key string) (any, error)
	// Del(ctx context.Context, key string) error
}

type Provider string

const (
	HashicorpVault Provider = "hashicorp"
	AzureKeyVault  Provider = "azure"
)

type VaultManager struct {
	client *vault.Client
}

func (manager *VaultManager) Set(ctx context.Context, key string, val any) error {
	_, err := manager.client.Secrets.KvV2Write(ctx, "gateway", schema.KvV2WriteRequest{
		Data: map[string]any{
			key: val}})
	return err
}

func (manager *VaultManager) Get(ctx context.Context, key string) (any, error) {
	resp, err := manager.client.Secrets.KvV2Read(ctx, "gateway")
	return resp.Data.Data[key], err
}

func NewSecretManager(provider Provider) (SecretManager, error) {
	ctx := context.Background()

	switch provider {
	case HashicorpVault:
		address := utils.LoadEnvVariable("VAULT_ADDRESS")
		client, err := vault.New(
			vault.WithAddress(address),
			vault.WithRequestTimeout(30*time.Second),
		)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Auth.UserpassLogin(ctx, utils.LoadEnvVariable("VAULT_USERNAME"), schema.UserpassLoginRequest{
			Password: utils.LoadEnvVariable("VAULT_PASSWORD")})
		if err != nil {
			log.Fatal(err)
		}

		if err := client.SetToken(resp.Auth.ClientToken); err != nil {
			log.Fatal(err)
		}
		return &VaultManager{client: client}, nil
	default:
		return nil, nil
	}
}
