// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !configs
// +build !configs

// This file is used for walmart internal to run KF specific configs.
// We will be removing this file in future.

package kf

import (
	"github.com/rs/zerolog/log"
)

func (b *BPF) RunKFConfigs() error {
	log.Warn().Msg("Implement custom KF specific configs")
	return nil
}
