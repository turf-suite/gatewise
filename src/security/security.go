package security

import (
	"log"
	"turf-auth/src/utils"
)

var TokenSigner *SigningKeyManager
var Secrets SecretManager
var err error

func init() {
	Secrets, err = NewSecretManager(Provider(utils.LoadEnvVariable("SECRETS_PROVIDER")))
	if err != nil {
		log.Fatal(err)
	}
	TokenSigner = &SigningKeyManager{secrets: Secrets}
}
