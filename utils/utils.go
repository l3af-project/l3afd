// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package utils provides helper functions for l3afd
package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ReplaceDotsWithUnderscores replaces all dots in the given string with underscores.
func ReplaceDotsWithUnderscores(version string) string {
	return strings.ReplaceAll(version, ".", "_")
}

// LinkPinPath builds the formatted link pin path string.
func LinkPinPath(bpfMapDefaultPath, ifaceName, programName, version, progType string) string {
	return filepath.Join(bpfMapDefaultPath, "links", ifaceName, programName, version, fmt.Sprintf("%s_%s", programName, progType))
}

// ProgPinPath builds the formatted program pin path string.
func ProgPinPath(bpfMapDefaultPath, ifaceName, programName, version, entryFunctionName, progType string) string {
	return filepath.Join(bpfMapDefaultPath, "progs", ifaceName, programName, version, fmt.Sprintf("%s_%s", entryFunctionName, progType))
}
