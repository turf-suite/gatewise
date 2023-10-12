package security

import (
	"context"
	"log"
	"time"
	"turf-gatewise/utils"

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
	// ctx := context.Background()

	switch provider {
	case HashicorpVault:
		address := utils.LoadEnvVariable("VAULT_ADDRESS")
		client, err := vault.New(
			vault.WithAddress(address),
			vault.WithRequestTimeout(30*time.Second),
		)
		if err != nil {
			log.Fatalf("Error connecting to Hashicorp Vault: %v", err)
		}
		if err := client.SetToken(utils.LoadEnvVariable("VAULT_ROOT_TOKEN")); err != nil {
			log.Fatalf("Error authenticating with Hashicorp Vault Client: %v", err)
		}
		return &VaultManager{client: client}, nil
	default:
		return nil, nil
	}
}
