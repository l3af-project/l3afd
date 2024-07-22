// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !configs
// +build !configs

// This file is used for walmart internal to run BPF specific configs.
// We will be removing this file in future.

package bpfprogs

import (
	"github.com/rs/zerolog/log"
)

func (b *BPF) RunBPFConfigs() error {
	log.Warn().Msg("Implement custom BPF specific configs")
	return nil
}
