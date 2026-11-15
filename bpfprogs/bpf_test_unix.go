// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !WINDOWS
// +build !WINDOWS

package bpfprogs

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/l3af-project/l3afd/v2/models"

	"github.com/cilium/ebpf/link"
)

func GetTestNonexecutablePathName() string {
	return "/var/log/syslog"
}

func GetTestExecutablePathName() string {
	return "/bin/date"
}

func GetTestExecutablePath() string {
	return "/bin"
}

func GetTestExecutableName() string {
	return "date"
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

// Test_ifindexMatches exercises the pure ifindex-vs-interface comparison
// that backs isAttachedToInterface's XDP/TCX mismatch detection, using the
// real "lo" loopback interface (present on every host) as a stable,
// non-privileged source of a genuine ifindex - no kernel eBPF calls
// required.
func Test_ifindexMatches(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface available on this host")
	}

	tests := []struct {
		name        string
		linkIfindex uint32
		ifaceName   string
		want        bool
	}{
		{
			name:        "MatchingIfindex",
			linkIfindex: uint32(lo.Index),
			ifaceName:   "lo",
			want:        true,
		},
		{
			name:        "DriftedIfindex",
			linkIfindex: uint32(lo.Index) + 1000,
			ifaceName:   "lo",
			want:        false,
		},
		{
			name:        "UnknownInterfaceName",
			linkIfindex: uint32(lo.Index),
			ifaceName:   "nosuchif0",
			want:        false,
		},
		{
			name:        "ZeroIfindexIsMismatch",
			linkIfindex: 0,
			ifaceName:   "nosuchif0",
			want:        false,
		},
		{
			// Same zero-ifindex check, but paired with a real interface name
			// that would otherwise resolve and compare fine. This fails loudly
			// if the zero-check is ever reordered to run after the
			// net.InterfaceByName lookup instead of before it.
			name:        "ZeroIfindexIsMismatchEvenWithValidIface",
			linkIfindex: 0,
			ifaceName:   "lo",
			want:        false,
		},
		{
			// No ifaceName to resolve a mismatch against - treated as
			// unknown/attached rather than a false-positive mismatch.
			name:        "ZeroIfindexEmptyIfaceNameTreatedAsUnknown",
			linkIfindex: 0,
			ifaceName:   "",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ifindexMatches(tt.linkIfindex, tt.ifaceName); got != tt.want {
				t.Errorf("ifindexMatches(%d, %q) = %v, want %v", tt.linkIfindex, tt.ifaceName, got, tt.want)
			}
		})
	}
}

// Test_isAttachedToInterface covers the short-circuit paths of the
// interface-attachment check used by IsLoaded. Programs without a
// link-based attachment (b.Link == nil - classic TC filters, chained or
// user-daemon programs) or without a recorded IfaceName must never be
// reported as "not attached", regardless of the value of the other field.
//
// Exercising the XDP/TCX mismatch branches themselves (info.XDP()/
// info.TCX(), i.e. going through a real link.Link) needs a kernel-backed
// link, which isn't obtainable in this unit test environment; that part of
// the dispatch is covered indirectly by Test_ifindexMatches above and
// needs to be verified end-to-end on a Linux host with eBPF support.
func Test_isAttachedToInterface(t *testing.T) {
	tests := []struct {
		name      string
		link      link.Link
		ifaceName string
		want      bool
	}{
		{
			name:      "NilLinkWithIfaceName",
			link:      nil,
			ifaceName: "eth0",
			want:      true,
		},
		{
			name:      "NilLinkNoIfaceName",
			link:      nil,
			ifaceName: "",
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:   models.BPFProgram{Name: "testprog"},
				Link:      tt.link,
				IfaceName: tt.ifaceName,
			}
			if got := b.isAttachedToInterface(); got != tt.want {
				t.Errorf("BPF.isAttachedToInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}
