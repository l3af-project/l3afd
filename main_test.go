// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/l3af-project/l3afd/config"
)

func TestTestConfigValid(t *testing.T) {
	// skip if file DNE
	f, err := os.Open("config/l3afd.cfg")
	if err != nil {
		t.Skip("l3afd.cfg not found")
	}
	f.Close()
	if _, err := config.ReadConfig("config/l3afd.cfg"); err != nil {
		t.Errorf("Unable to read l3afd config: %s", err)
	}
}
