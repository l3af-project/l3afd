// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
// +build !WINDOWS

package signals

import (
	"os"
	"syscall"
)

var ShutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
