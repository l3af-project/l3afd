// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !WINDOWS
// +build !WINDOWS

package kf

import (
	"fmt"
	"os"
)

func GetTestNonexecutablePathName() string {
	return "/var/log/syslog"
}

func GetTestExecutablePathName() string {
	return "/bin/ls"
}

func GetTestExecutablePath() string {
	return "/bin"
}

func GetTestExecutableName() string {
	return "ls"
}

// assertExecutable checks for executable permissions
func assertExecutable(fPath string) error {
	info, err := os.Stat(fPath)
	if err != nil {
		return fmt.Errorf("could not stat file: %s with error: %w", fPath, err)
	}

	if (info.Mode()&os.ModePerm)&os.FileMode(executePerm) == 0 {
		return fmt.Errorf("file: %s, is not executable", fPath)
	}
	return nil
}
