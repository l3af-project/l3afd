// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"

	"github.com/l3af-project/l3afd/config"
	"github.com/rs/zerolog/log"

	vault "github.com/hashicorp/vault/api"
)

func ValidateToken(ctx context.Context, conf *config.Config, reqToken string) (bool, int) {

	var jwtSecretKey string
	if conf.SecretsType == "ENV" {
		jwtSecretKey = os.Getenv(conf.SecretsKey)
	} else if conf.SecretsType == "VAULT" {
		config := vault.DefaultConfig()
		config.Address = conf.VaultURL
		client, err := vault.NewClient(config)
		if err != nil {
			log.Error().Msgf("unable to initialize Vault client: %v", err)
			return false, http.StatusInternalServerError
		}

		secret, err := client.KVv2("secret").Get(ctx, conf.SecretsKey)
		if err != nil {
			log.Error().Msgf("unable to read secret: %v", err)
			return false, http.StatusInternalServerError
		}
		var ok bool
		jwtSecretKey, ok = secret.Data["value"].(string)
		if !ok {
			log.Error().Msgf("value type assertion failed: %T %#v", secret.Data["value"], secret.Data["value"])
			return false, http.StatusInternalServerError
		}
	} else {
		log.Error().Msgf("unknown secret key storage type")
		return false, http.StatusInternalServerError
	}

	if len(jwtSecretKey) < 1 {
		log.Error().Msgf("secret key is undefined")
		return false, http.StatusInternalServerError
	}

	token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		log.Error().Msgf("token validation error - %v", err)
		return false, http.StatusUnauthorized
	}

	if !token.Valid {
		log.Error().Msgf("invalid token")
		return false, http.StatusUnauthorized
	}

	return true, http.StatusOK
}
