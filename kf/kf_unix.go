// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !WINDOWS
// +build !WINDOWS

// Package kf provides primitives for l3afd's network function configs.
package kf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/rs/zerolog/log"
	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"
)

// DisableLRO - XDP programs are failing when LRO is enabled, to fix this we use to manually disable.
// # ethtool -K ens7 lro off
// # ethtool -k ens7 | grep large-receive-offload
// large-receive-offload: off
func DisableLRO(ifaceName string) error {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		err = fmt.Errorf("ethtool failed to get the handle %v", err)
		log.Error().Err(err).Msg("")
		return err
	}
	defer ethHandle.Close()

	config := make(map[string]bool, 1)
	config["rx-lro"] = false
	if err := ethHandle.Change(ifaceName, config); err != nil {
		err = fmt.Errorf("ethtool failed to disable LRO on %s with err %v", ifaceName, err)
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
		return errors.New("failed to set prlimit")
	}

	return nil
}

// Set process resource limits only non-zero value
func (b *BPF) SetPrLimits() error {
	var rlimit unix.Rlimit

	if b.Cmd == nil {
		return errors.New("no Process to set limits")
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

// ProcessTerminate - Send sigterm to the process
func (b *BPF) ProcessTerminate() error {
	if err := b.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("BPFProgram %s SIGTERM failed with error: %v", b.Program.Name, err)
	}
	return nil
}

// VerifyNMountBPFFS - Mounting bpf filesystem
func VerifyNMountBPFFS() error {
	dstPath := "/sys/fs/bpf"
	srcPath := "bpffs"
	fstype := "bpf"
	flags := 0

	mnts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to read procfs: %v", err)
	}

	if !strings.Contains(string(mnts), dstPath) {
		log.Warn().Msg("bpf filesystem is not mounted going to mount")
		if err = syscall.Mount(srcPath, dstPath, fstype, uintptr(flags), ""); err != nil {
			return fmt.Errorf("unable to mount %s at %s: %s", srcPath, dstPath, err)
		}
	}

	return VerifyNMountTraceFS()
}

// VerifyNMounTraceFS - Mounting trace filesystem
func VerifyNMountTraceFS() error {
	dstPath := "/sys/kernel/debug/tracing"
	srcPath := "tracefs"
	fstype := "tracefs"
	flags := syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_RELATIME

	mnts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return fmt.Errorf("failed to read procfs: %v", err)
	}

	if !strings.Contains(string(mnts), dstPath) {
		log.Warn().Msgf(" %s filesystem is not mounted going to mount", dstPath)
		if _, err = os.Stat(dstPath); err != nil {
			log.Warn().Msgf(" %s directory doesn't exists, creating", dstPath)
			if err := os.Mkdir(dstPath, 0700); err != nil {
				return fmt.Errorf("unable to create mount point %s : %s", dstPath, err)
			}
		}
		if err = syscall.Mount(srcPath, dstPath, fstype, uintptr(flags), ""); err != nil {
			return fmt.Errorf("unable to mount %s at %s: %s", srcPath, dstPath, err)
		}
	}

	return nil
}

// This method get the Linux distribution Codename. This logic works on ubuntu
// Here assumption is all edge nodes are running with lsb modules.
// It returns empty string in case of error
func GetPlatform() (string, error) {

	linuxDistrib := execCommand("lsb_release", "-cs")
	var out bytes.Buffer
	linuxDistrib.Stdout = &out

	if err := linuxDistrib.Run(); err != nil {
		return "", fmt.Errorf("l3afd/nf : Failed to run command with error: %v", err)
	}

	return strings.TrimSpace(out.String()), nil
}

func IsProcessRunning(pid int, name string) (bool, error) {
	procState, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false, fmt.Errorf("BPF Program not running %s because of error: %v", name, err)
	}
	var u1, u2, state string
	_, err = fmt.Sscanf(string(procState), "%s %s %s", &u1, &u2, &state)
	if err != nil {
		return false, fmt.Errorf("failed to scan proc state with error: %v", err)
	}
	if state == "Z" {
		return false, fmt.Errorf("process %d in Zombie state", pid)
	}

	return true, nil
}

// VerifyNCreateTCDirs - Creating BPF sudo FS for pinning TC maps
func VerifyNCreateTCDirs() error {
	path := "/sys/fs/bpf/tc/globals"
	if _, err := os.Stat(path); err == nil {
		log.Debug().Msgf(" %s tc directory exists", path)
		return nil
	}
	log.Info().Msgf(" %s tc directory doesn't exists, creating", path)
	err := os.MkdirAll(path, 0700)
	if err != nil {
		return fmt.Errorf("unable to create directories to pin tc maps %s : %s", path, err)
	}
	return nil
}
