// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !WINDOWS
// +build !WINDOWS

// Package bpfprogs provides primitives for l3afd's network function configs.
package bpfprogs

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/l3af-project/l3afd/v2/models"
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
		return fmt.Errorf("BPFProgram %s SIGTERM failed with error: %w", b.Program.Name, err)
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
		return fmt.Errorf("failed to read procfs: %w", err)
	}

	if !strings.Contains(string(mnts), dstPath) {
		log.Warn().Msg("bpf filesystem is not mounted going to mount")
		if err = syscall.Mount(srcPath, dstPath, fstype, uintptr(flags), ""); err != nil {
			return fmt.Errorf("unable to mount %s at %s: %w", srcPath, dstPath, err)
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
		return fmt.Errorf("failed to read procfs: %w", err)
	}

	if !strings.Contains(string(mnts), dstPath) {
		log.Warn().Msgf(" %s filesystem is not mounted going to mount", dstPath)
		if _, err = os.Stat(dstPath); err != nil {
			log.Warn().Msgf(" %s directory doesn't exists, creating", dstPath)
			if err := os.Mkdir(dstPath, 0700); err != nil {
				return fmt.Errorf("unable to create mount point %s : %w", dstPath, err)
			}
		}
		if err = syscall.Mount(srcPath, dstPath, fstype, uintptr(flags), ""); err != nil {
			return fmt.Errorf("unable to mount %s at %s: %w", srcPath, dstPath, err)
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
		return "", fmt.Errorf("l3afd/nf : Failed to run command with error: %w", err)
	}

	return strings.TrimSpace(out.String()), nil
}

func IsProcessRunning(pid int, name string) (bool, error) {
	procState, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false, fmt.Errorf("BPF Program not running %s because of error: %w", name, err)
	}
	var u1, u2, state string
	_, err = fmt.Sscanf(string(procState), "%s %s %s", &u1, &u2, &state)
	if err != nil {
		return false, fmt.Errorf("failed to scan proc state with error: %w", err)
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
		return fmt.Errorf("unable to create directories to pin tc maps %s : %w", path, err)
	}
	return nil
}

// LoadTCAttachProgram - Load and attach tc root program filters or any tc program when chaining is disabled
func (b *BPF) LoadTCAttachProgram(ifaceName, direction string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Error().Err(err).Msgf("LoadTCAttachProgram - look up network iface %q", ifaceName)
		return err
	}
	if err := b.LoadBPFProgram(ifaceName); err != nil {
		return err
	}
	// verify and add attribute clsact
	tcgo, err := tc.Open(&tc.Config{})
	if err != nil {
		return fmt.Errorf("could not open rtnetlink socket for interface %s : %w", ifaceName, err)
	}
	clsactFound := false
	htbFound := false
	ingressFound := false
	var htbHandle uint32
	var ingressHandle uint32
	var parentHandle uint32
	// get all the qdiscs from all interfaces
	qdiscs, err := tcgo.Qdisc().Get()
	if err != nil {
		return fmt.Errorf("could not get qdiscs for interface %s : %w", ifaceName, err)
	}

	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			return fmt.Errorf("could not get interface %s from id %d: %w", ifaceName, qdisc.Ifindex, err)
		}
		if iface.Name == ifaceName {
			switch qdisc.Kind {
			case "clsact":
				clsactFound = true
			case "htb":
				htbFound = true
				htbHandle = qdisc.Msg.Handle
			case "ingress":
				ingressFound = true
				ingressHandle = qdisc.Msg.Handle
			default:
				log.Info().Msgf("Un-supported qdisc kind for interface %s ", ifaceName)
			}
		}
	}

	bpfRootProg := b.ProgMapCollection.Programs[b.Program.EntryFunctionName]

	var parent uint32
	var filter tc.Object

	progFD := uint32(bpfRootProg.FD())
	// Netlink attribute used in the Linux kernel
	bpfFlag := uint32(tc.BpfActDirect)
	if clsactFound {
		if direction == models.IngressType {
			parent = tc.HandleMinIngress
		} else if direction == models.EgressType {
			parent = tc.HandleMinEgress
		}

		filter = tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  0,
				Parent:  core.BuildHandle(tc.HandleRoot, parent),
				Info:    0x300,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &progFD,
					Flags: &bpfFlag,
				},
			},
		}
	} else if !clsactFound && !ingressFound && !htbFound {
		qdisc := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
				Parent:  tc.HandleIngress,
				Info:    0,
			},
			Attribute: tc.Attribute{
				Kind: "clsact",
			},
		}
		if err := tcgo.Qdisc().Add(&qdisc); err != nil {
			log.Info().Msgf("could not assign clsact to %s : %v, its already exists", ifaceName, err)
		}

		if direction == models.IngressType {
			parent = tc.HandleMinIngress
		} else if direction == models.EgressType {
			parent = tc.HandleMinEgress
		}

		filter = tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  0,
				Parent:  core.BuildHandle(tc.HandleRoot, parent),
				Info:    0x300,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &progFD,
					Flags: &bpfFlag,
				},
			},
		}
	} else if !clsactFound && ingressFound && htbFound {
		if direction == models.IngressType {
			parentHandle = ingressHandle
		} else if direction == models.EgressType {
			parentHandle = htbHandle
		}

		// parentNew needs to handle of HTB and ingress 1:, and ffff:
		filter = tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  0,
				Parent:  parentHandle,
				Info:    0x300,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &progFD,
					Flags: &bpfFlag,
				},
			},
		}
	} else {
		log.Info().Msgf("Unable to create qdisc object for interface %s", ifaceName)
	}

	// Storing Filter handle
	filterHandle := tcgo.Filter()
	// Attaching / Adding as filter
	if err := filterHandle.Add(&filter); err != nil {
		return fmt.Errorf("could not attach filter to interface %s for eBPF program %s : %w", ifaceName, b.Program.Name, err)
	}

	if b.HostConfig.BpfChainingEnabled {
		if err = b.UpdateProgramMap(ifaceName); err != nil {
			return err
		}
	}
	return nil
}

// UnloadTCProgram - Remove TC filters
func (b *BPF) UnloadTCProgram(ifaceName, direction string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Error().Err(err).Msgf("UnloadTCProgram - look up network iface %q", ifaceName)
		return err
	}

	tcgo, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Error().Err(err).Msgf("UnloadTCProgram - Unable to tc.Open(&tc.Config{}):  %q", ifaceName)
		return err
	}

	clsactFound := false
	htbFound := false
	ingressFound := false
	var htbHandle uint32
	var ingressHandle uint32
	var parentHandle uint32
	// get all the qdiscs from all interfaces
	qdiscs, err := tcgo.Qdisc().Get()
	if err != nil {
		log.Warn().Msgf("Could not get filters for interface \"%s\" direction %s ", ifaceName, direction)
		return fmt.Errorf("could not get filters for interface %s : %w", ifaceName, err)
	}
	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			return fmt.Errorf("could not get interface %s from id %d: %v", ifaceName, qdisc.Ifindex, err)
		}
		if iface.Name == ifaceName {
			switch qdisc.Kind {
			case "clsact":
				clsactFound = true
			case "htb":
				htbFound = true
				htbHandle = qdisc.Msg.Handle
			case "ingress":
				ingressFound = true
				ingressHandle = qdisc.Msg.Handle
			default:
				log.Info().Msgf("qdisc kind for %s : %v", ifaceName, err)
			}
		}
	}

	bpfRootProg := b.ProgMapCollection.Programs[b.Program.EntryFunctionName]
	// Storing Filter handle
	filterHandle := tcgo.Filter()
	var parent uint32
	var filter tc.Object

	if clsactFound && !ingressFound && !htbFound {
		if direction == models.IngressType {
			parent = tc.HandleMinIngress
		} else if direction == models.EgressType {
			parent = tc.HandleMinEgress
		}

		tcfilts, err := filterHandle.Get(&tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0x0,
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
		})

		if err != nil {
			log.Warn().Msgf("Could not get filters for interface \"%s\" direction %s ", ifaceName, direction)
			return fmt.Errorf("could not get filters for interface %s : %v", ifaceName, err)
		}

		progFD := uint32(bpfRootProg.FD())
		// Netlink attribute used in the Linux kernel
		bpfFlag := uint32(tc.BpfActDirect)

		filter = tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  0,
				Parent:  core.BuildHandle(tc.HandleRoot, parent),
				Info:    tcfilts[0].Msg.Info,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &progFD,
					Flags: &bpfFlag,
				},
			},
		}
	} else if !clsactFound && ingressFound && htbFound {
		if direction == models.EgressType {
			parentHandle = htbHandle
			// _ = pa("parentNew...1 ", parentNew)
		} else if direction == models.IngressType {
			parentHandle = ingressHandle
		}
		tcfilts, err := filterHandle.Get(&tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0x0,
			Parent:  parentHandle,
		})

		if err != nil {
			log.Warn().Msgf("Could not get filters for interface \"%s\" direction %s ", ifaceName, direction)
			return fmt.Errorf("could not get filters for interface %s : %v", ifaceName, err)
		}

		progFD := uint32(bpfRootProg.FD())
		// Netlink attribute used in the Linux kernel
		bpfFlag := uint32(tc.BpfActDirect)

		var tcFilterIndex int
		for i, tcfilt := range tcfilts {
			// finding the Info field of the relevant BPF filter among all set filters for that qdisc
			if tcfilt.Attribute.Kind == "bpf" {
				tcFilterIndex = i
			}
		}
		// Add a check for if tcFilterIndex out of bounds
		filter = tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  0,
				Parent:  parentHandle,
				Info:    tcfilts[tcFilterIndex].Msg.Info,
			},
			Attribute: tc.Attribute{
				Kind: "bpf",
				BPF: &tc.Bpf{
					FD:    &progFD,
					Flags: &bpfFlag,
				},
			},
		}
	}

	// Detaching / Deleting filter
	if err := filterHandle.Delete(&filter); err != nil {
		return fmt.Errorf("could not dettach tc filter for interface %s : Direction: %v, parentHandle: %v, Error:%w", ifaceName, direction, parentHandle, err)
	}

	return nil
}
