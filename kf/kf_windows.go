// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
// +build WINDOWS

// Package kf provides primitives for l3afd's network function configs.
package kf

// DisableLRO - XDP programs are failing when Large Receive Offload is enabled, to fix this we use to manually disable.
func DisableLRO(ifaceName string) error {
	return nil
}

// Set process resource limits only non-zero value
func (b *BPF) SetPrLimits() error {
	return nil
}

// VerifyNMountBPFFS - Mounting bpf filesystem
func VerifyNMountBPFFS() error {
	return nil
}

func GetPlatform() (string, error) {
    return "Windows", nil
}
