// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package utils provides helper functions for l3afd
package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GetKernelVersion - reads the kernel version from /proc/version
func GetKernelVersion() (string, error) {
	osVersion, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("failed to read procfs: %v", err)
	}
	var u1, u2, kernelVersion string
	_, err = fmt.Sscanf(string(osVersion), "%s %s %s", &u1, &u2, &kernelVersion)
	if err != nil {
		return "", fmt.Errorf("failed to scan procfs version: %v", err)
	}

	return kernelVersion, nil
}

// CheckTCXSupport - verifies kernel version is 6.8 or above
func CheckTCXSupport() bool {
	const minVerLen = 2
	const minMajorKernelVer = 6
	const minMinorKernelVer = 8

	kernelVersion, err := GetKernelVersion()
	if err != nil {
		return false
	}

	// validate version
	ver := strings.Split(kernelVersion, ".")
	if len(ver) < minVerLen {
		return false
	}
	majorVer, err := strconv.Atoi(ver[0])
	if err != nil {
		return false
	}
	minorVer, err := strconv.Atoi(ver[1])
	if err != nil {
		return false
	}

	if majorVer > minMajorKernelVer {
		return true
	}
	if majorVer == minMajorKernelVer && minorVer >= minMinorKernelVer {
		return true
	}

	return false
}

// ReplaceDotsWithUnderscores replaces all dots in the given string with underscores.
func ReplaceDotsWithUnderscores(version string) string {
	return strings.ReplaceAll(version, ".", "_")
}

// LinkPinPath builds the formatted link pin path string.
func LinkPinPath(bpfMapDefaultPath, ifaceName, programName, version, progType string) string {
	return filepath.Join(bpfMapDefaultPath, "links", ifaceName, programName, version, fmt.Sprintf("%s_%s", programName, progType))
}

// TCLinkPinPath builds the formatted link pin path string.
func TCLinkPinPath(bpfMapDefaultPath, ifaceName, programName, version, progType, direction string) string {
	return filepath.Join(bpfMapDefaultPath, "links", ifaceName, programName, version, fmt.Sprintf("%s_%s_%s", programName, progType, direction))
}

// ProgPinPath builds the formatted program pin path string.
func ProgPinPath(bpfMapDefaultPath, ifaceName, programName, version, entryFunctionName, progType string) string {
	return filepath.Join(bpfMapDefaultPath, "progs", ifaceName, programName, version, fmt.Sprintf("%s_%s", entryFunctionName, progType))
}
