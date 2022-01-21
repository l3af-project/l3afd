// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
// +build !WINDOWS

// Package kf provides primitives for l3afd's network function configs.
package kf

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/models"

	"github.com/rs/zerolog/log"
	"github.com/safchain/ethtool"
)

// DisableLRO - XDP programs are failing when LRO is enabled, to fix this we use to manually disable.
// # ethtool -K ens7 lro off
// # ethtool -k ens7 | grep large-receive-offload
// large-receive-offload: off
func DisableLRO(ifaceName string) error {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		err = fmt.Errorf("ethtool failed to get the handle %w", err)
		log.Error().Err(err).Msg("")
		return err
	}
	defer ethHandle.Close()

	config := make(map[string]bool, 1)
	config["rx-lro"] = false
	if err := ethHandle.Change(ifaceName, config); err != nil {
		err = fmt.Errorf("ethtool failed to disable LRO on %s with err %w", ifaceName, err)
		log.Error().Err(err).Msg("")
		return err
	}

	return nil
}

// prLimit set the memory and cpu limits for the bpf program
func prLimit(pid int, limit uintptr, rlimit *unix.Rlimit) error {
	_, _, errno := unix.RawSyscall6(unix.SYS_PRLIMIT64,
		uintptr(pid),
		limit,
		uintptr(unsafe.Pointer(rlimit)),
		0, 0, 0)

	if errno != 0 {
		log.Error().Msgf("Failed to set prlimit for process %d and errorno %d", pid, errno)
		return errors.New("Failed to set prlimit")
	}

	return nil
}

// Set process resource limits only non-zero value
func (b *BPF) SetPrLimits() error {
	var rlimit unix.Rlimit

	if b.Cmd == nil {
		return errors.New("No Process to set limits")
	}

	if b.Program.Memory != 0 {
		rlimit.Cur = uint64(b.Program.Memory)
		rlimit.Max = uint64(b.Program.Memory)

		if err := prLimit(b.Cmd.Process.Pid, unix.RLIMIT_AS, &rlimit); err != nil {
			log.Error().Err(err).Msgf("Failed to set Memory limits - %s", b.Program.Name)
		}
	}

	if b.Program.CPU != 0 {
		rlimit.Cur = uint64(b.Program.CPU)
		rlimit.Max = uint64(b.Program.CPU)
		if err := prLimit(b.Cmd.Process.Pid, unix.RLIMIT_CPU, &rlimit); err != nil {
			log.Error().Err(err).Msgf("Failed to set CPU limits - %s", b.Program.Name)
		}
	}

	return nil
}
