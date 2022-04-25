// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !admind
// +build !admind

// This file is used for walmart internal to register with management server.
// We will be removing this file in future.

package main

import (
	"github.com/l3af-project/l3afd/config"

	"github.com/rs/zerolog/log"
)

func registerL3afD(conf *config.Config) error {
	log.Warn().Msg("Implement custom registration with management server")
	return nil
}
