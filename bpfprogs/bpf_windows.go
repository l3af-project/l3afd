// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build WINDOWS
// +build WINDOWS

// Package bpfprogs provides primitives for l3afd's network function configs.
package bpfprogs

import (
	"errors"
	"fmt"
	"os"
)

// DisableLRO - XDP programs are failing when Large Receive Offload is enabled, to fix this we use to manually disable.
func DisableLRO(ifaceName string) error {
	return nil
}

// Set process resource limits only non-zero value
func (b *BPF) SetPrLimits() error {
	if b.Cmd == nil {
		return errors.New("no Process to set limits")
	}
	return nil
}

// VerifyNMountBPFFS - Mounting bpf filesystem
func VerifyNMountBPFFS() error {
	return nil
}

func GetPlatform() (string, error) {
	return "Windows", nil
}

func IsProcessRunning(pid int, name string) (bool, error) {
	_, err := os.FindProcess(pid)
	if err != nil {
		return false, fmt.Errorf("BPF Program not running %s because of error: %w", name, err)
	}
	return true, nil
}

// ProcessTerminate - Kills the process
func (b *BPF) ProcessTerminate() error {
	if err := b.Cmd.Process.Kill(); err != nil {
		return fmt.Errorf("BPFProgram %s kill failed with error: %w", b.Program.Name, err)
	}
	return nil
}

// VerifyNCreateTCDirs - Creating BPF sudo FS for pinning TC maps
func VerifyNCreateTCDirs() error {
	return nil
}

// LoadTCAttachProgram - not implemented in windows
func (b *BPF) LoadTCAttachProgram(ifaceName, direction string) error {
	// not implement nothing todo
	return fmt.Errorf("LoadTCAttachProgram - TC programs Unsupported on windows")
}

// UnloadTCProgram - Remove TC filters
func (b *BPF) UnloadTCProgram(ifaceName, direction string) error {
	return fmt.Errorf("UnloadTCProgram - TC programs Unsupported on windows")
}
