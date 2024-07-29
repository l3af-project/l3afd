// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package bpfprogs provides primitives for l3afd's network function configs.
package bpfprogs

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rs/zerolog/log"
)

type NFConfigs struct {
	Ctx            context.Context
	HostName       string
	HostInterfaces map[string]bool
	//	configs        sync.Map // key: string, val: *models.L3afDNFConfigDetail
	// These holds bpf programs in the list
	// map keys are network iface names index's are seq_id, position in the chain
	// root element will be root program
	IngressXDPBpfs map[string]*list.List
	IngressTCBpfs  map[string]*list.List
	EgressTCBpfs   map[string]*list.List
	ProbesBpfs     list.List

	HostConfig    *config.Config
	ProcessMon    *PCheck
	BpfMetricsMon *BpfMetrics

	// keep track of interfaces
	Ifaces map[string]string

	Mu *sync.Mutex
}

func NewNFConfigs(ctx context.Context, host string, hostConf *config.Config, pMon *PCheck, metricsMon *BpfMetrics) (*NFConfigs, error) {
	nfConfigs := &NFConfigs{
		Ctx:            ctx,
		HostName:       host,
		HostConfig:     hostConf,
		IngressXDPBpfs: make(map[string]*list.List),
		IngressTCBpfs:  make(map[string]*list.List),
		EgressTCBpfs:   make(map[string]*list.List),
		Mu:             new(sync.Mutex),
	}

	var err error
	if nfConfigs.HostInterfaces, err = getHostInterfaces(); err != nil {
		errOut := fmt.Errorf("%s failed to get network interfaces %w", host, err)
		log.Error().Err(errOut)
		return nil, errOut
	}

	nfConfigs.ProcessMon = pMon
	nfConfigs.ProcessMon.PCheckStart(nfConfigs.IngressXDPBpfs, nfConfigs.IngressTCBpfs, nfConfigs.EgressTCBpfs, &nfConfigs.ProbesBpfs)
	nfConfigs.BpfMetricsMon = metricsMon
	nfConfigs.BpfMetricsMon.BpfMetricsStart(nfConfigs.IngressXDPBpfs, nfConfigs.IngressTCBpfs, nfConfigs.EgressTCBpfs, &nfConfigs.ProbesBpfs)
	return nfConfigs, nil
}

// Close stop all the eBPF Programs and delete elements in the list
func (c *NFConfigs) Close(ctx context.Context) error {
	ticker := time.NewTicker(c.HostConfig.ShutdownTimeout)
	defer ticker.Stop()
	doneCh := make(chan struct{})
	var wg sync.WaitGroup

	// wait for waitGroup to shut down
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for ifaceName := range c.IngressXDPBpfs {
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.XDPIngressType); err != nil {
				log.Warn().Err(err).Msg("failed to Close Ingress XDP BPF Program")
			}
			delete(c.IngressXDPBpfs, ifaceName)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for ifaceName := range c.IngressTCBpfs {
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.IngressType); err != nil {
				log.Warn().Err(err).Msg("failed to Close Ingress TC BPF Program")
			}
			delete(c.IngressTCBpfs, ifaceName)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for ifaceName := range c.EgressTCBpfs {
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.EgressType); err != nil {
				log.Warn().Err(err).Msg("failed to Close Egress TC BPF Program")
			}
			delete(c.EgressTCBpfs, ifaceName)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.StopNRemoveAllBPFProbePrograms(); err != nil {
			log.Warn().Err(err).Msg("failed to Close Probe BPF Programs")
		}

	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ticker.C:
		// didn't close successfully
		return fmt.Errorf("nfconfig close didn't got processed in shutdownInterval ms %v", c.HostConfig.ShutdownTimeout)
	case <-doneCh:
		// we deleted successfully
	}

	return nil
}

// Check for XDP programs are not loaded then initialise the array
// Check for XDP root program is running for a interface. if not loaded it
func (c *NFConfigs) VerifyAndStartXDPRootProgram(ifaceName, direction string) error {

	if err := DisableLRO(ifaceName); err != nil {
		return fmt.Errorf("failed to disable lro %w", err)
	}
	if err := VerifyNMountBPFFS(); err != nil {
		return fmt.Errorf("failed to mount bpf file system with err %w", err)
	}

	// chaining is disabled nothing to do
	if !c.HostConfig.BpfChainingEnabled {
		return nil
	}

	if c.IngressXDPBpfs[ifaceName].Len() == 0 {
		rootBpf, err := LoadRootProgram(ifaceName, direction, models.XDPType, c.HostConfig)
		if err != nil {
			return fmt.Errorf("failed to load %s xdp root program: %w", direction, err)
		}
		log.Info().Msg("ingress xdp root program attached")
		c.IngressXDPBpfs[ifaceName].PushFront(rootBpf)
	}

	return nil
}

// Check for TC root program is running for a interface. If not start it
func (c *NFConfigs) VerifyAndStartTCRootProgram(ifaceName, direction string) error {

	if err := VerifyNMountBPFFS(); err != nil {
		return fmt.Errorf("failed to mount bpf file system with err : %w", err)
	}
	if err := VerifyNCreateTCDirs(); err != nil {
		return fmt.Errorf("failed to create tc/global diretories with err: %w", err)
	}
	// Check for chaining flag
	if !c.HostConfig.BpfChainingEnabled {
		return nil
	}

	if direction == models.IngressType {
		if c.IngressTCBpfs[ifaceName].Len() == 0 { //Root program is not running start then
			rootBpf, err := LoadRootProgram(ifaceName, direction, models.TCType, c.HostConfig)
			if err != nil {
				return fmt.Errorf("failed to load %s tc root program: %w", direction, err)
			}
			log.Info().Msg("ingress tc root program attached")
			c.IngressTCBpfs[ifaceName].PushFront(rootBpf)
		}
	} else {
		if c.EgressTCBpfs[ifaceName].Len() == 0 { //Root program is not running start then
			rootBpf, err := LoadRootProgram(ifaceName, direction, models.TCType, c.HostConfig)
			if err != nil {
				return fmt.Errorf("failed to load %s tc root program: %w", direction, err)
			}
			log.Info().Msg("egress tc root program attached")
			c.EgressTCBpfs[ifaceName].PushFront(rootBpf)
		}
	}

	return nil
}

// This method inserts the element at the end of the list
func (c *NFConfigs) PushBackAndStartBPF(bpfProg *models.BPFProgram, ifaceName, direction string) error {

	log.Info().Msgf("PushBackAndStartBPF : iface %s, direction %s", ifaceName, direction)
	bpf := NewBpfProgram(c.Ctx, *bpfProg, c.HostConfig, ifaceName)
	var bpfList *list.List

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default: // we should never reach here
		return fmt.Errorf("unknown direction type")
	}

	if err := c.DownloadAndStartBPFProgram(bpfList.PushBack(bpf), ifaceName, direction); err != nil {
		return fmt.Errorf("failed to download and start the BPF %s iface %s direction %s with err: %w", bpfProg.Name, ifaceName, direction, err)
	}

	return nil
}

func (c *NFConfigs) DownloadAndStartBPFProgram(element *list.Element, ifaceName, direction string) error {
	if element == nil {
		return fmt.Errorf("element is nil pointer")
	}

	bpf := element.Value.(*BPF)

	if element.Prev() != nil {
		prevBPF := element.Prev().Value.(*BPF)
		bpf.PrevMapNamePath = prevBPF.MapNamePath
		bpf.PrevProgMapID = prevBPF.ProgMapID
		log.Info().Msgf("DownloadAndStartBPFProgram : program name %s previous program map name: %s", bpf.Program.Name, bpf.PrevMapNamePath)
	}

	if err := bpf.VerifyAndGetArtifacts(c.HostConfig); err != nil {
		return fmt.Errorf("failed to get artifacts %s with error: %w", bpf.Program.Artifact, err)
	}

	if err := bpf.Start(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
		return fmt.Errorf("failed to start bpf program %s with error: %w", bpf.Program.Name, err)
	}

	return nil
}

// Stopping all programs in order
func (c *NFConfigs) StopNRemoveAllBPFPrograms(ifaceName, direction string) error {

	var bpfList *list.List

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
		c.IngressXDPBpfs[ifaceName] = nil
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
		c.IngressTCBpfs[ifaceName] = nil
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
		c.EgressTCBpfs[ifaceName] = nil
	default: // we should never reach here
		return fmt.Errorf("unknown direction type %s", direction)
	}

	if bpfList == nil {
		log.Warn().Msgf("no %s ebpf programs to stop", direction)
		return nil
	}

	for e := bpfList.Front(); e != nil; {
		data := e.Value.(*BPF)
		if err := data.Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
			return fmt.Errorf("failed to stop program %s direction %s with err :%w", data.Program.Name, direction, err)
		}
		nextBPF := e.Next()
		bpfList.Remove(e)
		e = nextBPF
	}

	return nil
}

// StopNRemoveAllBPFProbePrograms Stopping all probe programs in order
func (c *NFConfigs) StopNRemoveAllBPFProbePrograms() error {

	for e := c.ProbesBpfs.Front(); e != nil; {
		data := e.Value.(*BPF)
		if err := data.Stop("", "", false); err != nil {
			return fmt.Errorf("failed to stop probe program %s with err :%w", data.Program.Name, err)
		}
		nextBPF := e.Next()
		c.ProbesBpfs.Remove(e)
		e = nextBPF
	}

	return nil
}

// VerifyNUpdateBPFProgram - This method checks the following conditions
// 1. BPF Program already running with no change
// 2. BPF Program running but needs to stop (admin_status == disabled)
// 3. BPF Program running but needs version update
// 4. BPF Program running but position change (seq_id change)
// 5. BPF Program not running but needs to start.
// 6. BPF Program running but map args change, will update the map values (i.e. Array and Hash maps only)
// 7. BPF Program running but update args change, will invoke cmd_update with additional option --cmd=update
func (c *NFConfigs) VerifyNUpdateBPFProgram(bpfProg *models.BPFProgram, ifaceName, direction string) error {

	var bpfList *list.List
	if bpfProg == nil {
		return nil
	}

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if strings.Compare(data.Program.Name, bpfProg.Name) != 0 {
			continue
		}

		if reflect.DeepEqual(data.Program, *bpfProg) {
			// Nothing to do
			return nil
		}

		// Admin status change - disabled
		if data.Program.AdminStatus != bpfProg.AdminStatus {
			log.Info().Msgf("verifyNUpdateBPFProgram :admin_status change detected - disabling the program %s", data.Program.Name)
			data.Program.AdminStatus = bpfProg.AdminStatus
			if err := data.Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
				return fmt.Errorf("failed to stop to on admin_status change BPF %s iface %s direction %s admin_status %s with err %w", bpfProg.Name, ifaceName, direction, bpfProg.AdminStatus, err)
			}
			tmpNextBPF := e.Next()
			tmpPreviousBPF := e.Prev()
			bpfList.Remove(e)
			if tmpNextBPF != nil && tmpNextBPF.Prev() != nil { // relink the next element
				if err := c.LinkBPFPrograms(tmpNextBPF.Prev().Value.(*BPF), tmpNextBPF.Value.(*BPF)); err != nil {
					log.Error().Err(err).Msg("admin status disabled - failed LinkBPFPrograms")
					return fmt.Errorf("admin status disabled - failed LinkBPFPrograms %w", err)
				}
			}

			// if chaining is disabled prev will be nil
			if tmpPreviousBPF == nil && tmpNextBPF == nil {
				switch direction {
				case models.XDPIngressType:
					c.IngressXDPBpfs[ifaceName] = nil
				case models.IngressType:
					c.IngressTCBpfs[ifaceName] = nil
				case models.EgressType:
					c.EgressTCBpfs[ifaceName] = nil
				default:
					return fmt.Errorf("unknown direction type %s", direction)
				}
				return nil
			}

			// Check if list contains root program only then stop the root program.
			if tmpPreviousBPF.Prev() == nil && tmpPreviousBPF.Next() == nil {
				log.Info().Msg("no eBPF Programs are running, stopping root program")
				if c.HostConfig.BpfChainingEnabled {
					if err := c.StopRootProgram(ifaceName, direction); err != nil {
						return fmt.Errorf("failed to stop to root program  %s iface %s direction %s with err: %w", bpfProg.Name, ifaceName, direction, err)
					}
				}
			}
			return nil
		}

		// Version Change
		if data.Program.Version != bpfProg.Version || !reflect.DeepEqual(data.Program.StartArgs, bpfProg.StartArgs) {
			log.Info().Msgf("VerifyNUpdateBPFProgram : version update initiated - current version %s new version %s", data.Program.Version, bpfProg.Version)
			if err := data.Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
				return fmt.Errorf("failed to stop older version of network function BPF %s iface %s direction %s version %s with err: %w", bpfProg.Name, ifaceName, direction, bpfProg.Version, err)
			}

			data.Program = *bpfProg

			if err := c.DownloadAndStartBPFProgram(e, ifaceName, direction); err != nil {
				return fmt.Errorf("failed to download and start newer version of network function BPF %s version %s iface %s direction %s with err: %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
			}

			// update if not a last program
			if e.Next() != nil {
				data.PutNextProgFDFromID(int(e.Next().Value.(*BPF).ProgID))
			}

			return nil
		}

		// monitor maps change
		if !reflect.DeepEqual(data.Program.MonitorMaps, bpfProg.MonitorMaps) {
			log.Info().Msgf("monitor map list is mismatch - updated")
			data.Program.MonitorMaps = bpfProg.MonitorMaps
		}

		// Update CfgVersion
		data.Program.CfgVersion = bpfProg.CfgVersion

		// Seq ID Change
		if data.Program.SeqID != bpfProg.SeqID {
			log.Info().Msgf("VerifyNUpdateBPFProgram : seq id change detected %s current seq id %d new seq id %d", data.Program.Name, data.Program.SeqID, bpfProg.SeqID)

			// Update seq id
			data.Program.SeqID = bpfProg.SeqID

			if err := c.MoveToLocation(e, bpfList); err != nil {
				return fmt.Errorf("failed to move to new position in the chain BPF %s version %s iface %s direction %s with err: %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
			}
		}

		// map arguments change - basically any config change to ebpf program updating config maps
		if !reflect.DeepEqual(data.Program.MapArgs, bpfProg.MapArgs) {
			log.Info().Msg("maps_args are mismatched")
			data.Program.MapArgs = bpfProg.MapArgs
			data.UpdateBPFMaps(ifaceName, direction)
		}

		// update arguments change - basically any config change to ebpf program config maps using user program
		if !reflect.DeepEqual(data.Program.UpdateArgs, bpfProg.UpdateArgs) {
			log.Info().Msg("update_args are mismatched")
			data.Program.UpdateArgs = bpfProg.UpdateArgs
			data.UpdateArgs(ifaceName, direction)
		}

		return nil
	}

	log.Debug().Msgf("Program is not found in the list name %s", bpfProg.Name)
	// if not found in the list.
	if err := c.InsertAndStartBPFProgram(bpfProg, ifaceName, direction); err != nil {
		return fmt.Errorf("failed to insert and start BPFProgram to new location BPF %s version %s iface %s direction %s with err: %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
	}

	return nil
}

func (c *NFConfigs) MoveToLocation(element *list.Element, bpfList *list.List) error {

	if element == nil {
		return fmt.Errorf("MoveToLocation - element is nil")
	}
	bpf := element.Value.(*BPF)

	if bpfList == nil {
		log.Warn().Msg("ebpf program list is empty")
		return nil
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)

		if data.Program.SeqID >= bpf.Program.SeqID && data.Program.Name != bpf.Program.Name {
			if element.Next() != nil && element.Prev() != nil {
				if err := c.LinkBPFPrograms(element.Prev().Value.(*BPF), element.Next().Value.(*BPF)); err != nil {
					log.Error().Err(err).Msg("MoveToLocation - failed LinkBPFPrograms before move")
					return fmt.Errorf("MoveToLocation - failed LinkBPFPrograms before move %w", err)
				}
			} else if element.Next() == nil && element.Prev() != nil {
				if err := element.Prev().Value.(*BPF).RemoveNextProgFD(); err != nil {
					log.Error().Err(err).Msg("failed to remove program fd in map")
					return fmt.Errorf("failed to remove program fd in map %w", err)
				}
			}

			bpfList.MoveBefore(element, e)

			if err := c.LinkBPFPrograms(element.Prev().Value.(*BPF), element.Value.(*BPF)); err != nil {
				log.Error().Err(err).Msg("MoveToLocation - failed LinkBPFPrograms after move element to with prev prog")
				return fmt.Errorf("MoveToLocation - failed LinkBPFPrograms after move element to with prev prog %w", err)
			}

			if element.Next() != nil {
				if err := c.LinkBPFPrograms(element.Value.(*BPF), element.Next().Value.(*BPF)); err != nil {
					log.Error().Err(err).Msg("MoveToLocation - failed LinkBPFPrograms after move element to with next prog")
					return fmt.Errorf("MoveToLocation - failed LinkBPFPrograms after move element to with next prog %w", err)
				}
			}
			log.Info().Msgf("MoveToLocation : Moved - %s", element.Value.(*BPF).Program.Name)
			return nil
		}
	}

	log.Info().Msg("element seq id greater than last element in the list move to back of the list")
	if element.Next() != nil && element.Prev() != nil {
		if err := c.LinkBPFPrograms(element.Prev().Value.(*BPF), element.Next().Value.(*BPF)); err != nil {
			log.Error().Err(err).Msg("MoveToLocation - failed LinkBPFPrograms before MoveToBack element to with prev prog")
			return fmt.Errorf("MoveToLocation - failed LinkBPFPrograms before MoveToBack element to with prev prog %w", err)
		}
	}

	bpfList.MoveToBack(element)
	if element.Prev() != nil {
		if err := c.LinkBPFPrograms(element.Prev().Value.(*BPF), element.Value.(*BPF)); err != nil {
			log.Error().Err(err).Msg("MoveToLocation - failed LinkBPFPrograms after MoveToBack element to with prev prog")
			return fmt.Errorf("MoveToLocation - failed LinkBPFPrograms after MoveToBack element to with prev prog %w", err)
		}
	}

	if element.Next() == nil {
		if err := element.Value.(*BPF).RemoveNextProgFD(); err != nil {
			log.Error().Err(err).Msg("failed to remove MoveToBack program fd in map")
			return fmt.Errorf("failed to remove MoveToBack program fd in map %w", err)
		}
	}

	log.Info().Msgf("MoveToLocation : MoveToBack Moved - %s", element.Value.(*BPF).Program.Name)
	return nil
}

// InsertAndStartBPFProgram method for tc programs
func (c *NFConfigs) InsertAndStartBPFProgram(bpfProg *models.BPFProgram, ifaceName, direction string) error {

	var bpfList *list.List
	if bpfProg == nil {
		return fmt.Errorf("InsertAndStartBPFProgram - bpf program is nil")
	}

	if bpfProg.AdminStatus == models.Disabled {
		return nil
	}

	bpf := NewBpfProgram(c.Ctx, *bpfProg, c.HostConfig, ifaceName)

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	if bpfList == nil {
		log.Warn().Msgf("%s program list is empty", direction)
		return nil
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if data.Program.SeqID >= bpfProg.SeqID {
			tmpBPF := bpfList.InsertBefore(bpf, e)
			if err := c.DownloadAndStartBPFProgram(tmpBPF, ifaceName, direction); err != nil {
				return fmt.Errorf("failed to download and start network function %s version %s iface %s direction %s with err %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
			}

			if tmpBPF.Next() != nil {
				if err := c.LinkBPFPrograms(tmpBPF.Value.(*BPF), tmpBPF.Next().Value.(*BPF)); err != nil {
					log.Error().Err(err).Msg("InsertAndStartBPFProgram - failed LinkBPFPrograms after InsertBefore element to with next prog")
					return fmt.Errorf("InsertAndStartBPFProgram - failed LinkBPFPrograms after InsertBefore element to with next prog %w", err)
				}
			}
			return nil
		}
	}

	// insert at the end
	if err := c.PushBackAndStartBPF(bpfProg, ifaceName, direction); err != nil {
		return fmt.Errorf("failed to push back and start network function %s version %s iface %s direction %s with err: %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
	}

	return nil
}

// StopRootProgram -This method stops the root program, removes the root node from the list and reset the list to nil
func (c *NFConfigs) StopRootProgram(ifaceName, direction string) error {

	switch direction {
	case models.XDPIngressType:
		if c.IngressXDPBpfs[ifaceName] == nil {
			log.Warn().Msg("xdp root program is not running")
			return nil
		}

		if err := c.IngressXDPBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
			return fmt.Errorf("failed to stop xdp root program iface %s with err %w", ifaceName, err)
		}
		c.IngressXDPBpfs[ifaceName].Remove(c.IngressXDPBpfs[ifaceName].Front())
		c.IngressXDPBpfs[ifaceName] = nil
	case models.IngressType:
		if c.IngressTCBpfs[ifaceName] == nil {
			log.Warn().Msgf("tc root program %s not running", direction)
			return nil
		}
		if err := c.IngressTCBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
			return fmt.Errorf("failed to stop ingress tc root program on interface %s with err %w", ifaceName, err)
		}
		c.IngressTCBpfs[ifaceName].Remove(c.IngressTCBpfs[ifaceName].Front())
		c.IngressTCBpfs[ifaceName] = nil
	case models.EgressType:
		if c.EgressTCBpfs[ifaceName] == nil {
			log.Warn().Msgf("tc root program %s not running", direction)
			return nil
		}
		if err := c.EgressTCBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
			return fmt.Errorf("failed to stop egress tc root program on interface %s with err %w", ifaceName, err)
		}
		c.EgressTCBpfs[ifaceName].Remove(c.EgressTCBpfs[ifaceName].Front())
		c.EgressTCBpfs[ifaceName] = nil
	default:
		return fmt.Errorf("unknown direction type")
	}

	return nil
}

// Link BPF programs
func (c *NFConfigs) LinkBPFPrograms(leftBPF, rightBPF *BPF) error {
	log.Info().Msgf("LinkBPFPrograms : left BPF Prog %s right BPF Prog %s", leftBPF.Program.Name, rightBPF.Program.Name)
	rightBPF.PrevMapNamePath = leftBPF.MapNamePath
	rightBPF.PrevProgMapID = leftBPF.PrevProgMapID
	if err := leftBPF.PutNextProgFDFromID(int(rightBPF.ProgID)); err != nil {
		log.Error().Err(err).Msgf("LinkBPFPrograms - failed to update program fd in prev prog map before move")
		return fmt.Errorf("LinkBPFPrograms - failed to update program fd in prev prog prog map before move %w", err)
	}
	return nil
}

// BPFDetails - Method provides dump of BPFs for debug purpose
func (c *NFConfigs) BPFDetails(iface string) []*BPF {
	arrBPFDetails := make([]*BPF, 0)
	bpfList := c.IngressXDPBpfs[iface]
	if bpfList != nil {
		for e := bpfList.Front(); e != nil; e = e.Next() {
			arrBPFDetails = append(arrBPFDetails, e.Value.(*BPF))
		}
	}
	bpfList = c.IngressTCBpfs[iface]
	if bpfList != nil {
		for e := bpfList.Front(); e != nil; e = e.Next() {
			arrBPFDetails = append(arrBPFDetails, e.Value.(*BPF))
		}
	}
	bpfList = c.EgressTCBpfs[iface]
	if bpfList != nil {
		for e := bpfList.Front(); e != nil; e = e.Next() {
			arrBPFDetails = append(arrBPFDetails, e.Value.(*BPF))
		}
	}

	for e := c.ProbesBpfs.Front(); e != nil; e = e.Next() {
		arrBPFDetails = append(arrBPFDetails, e.Value.(*BPF))
	}

	return arrBPFDetails
}

func (c *NFConfigs) Deploy(ifaceName, HostName string, bpfProgs *models.BPFPrograms) error {

	if HostName != c.HostName {
		errOut := fmt.Errorf("provided bpf programs do not belong to this host")
		log.Error().Err(errOut)
		return errOut
	}

	if ifaceName == "" || bpfProgs == nil {
		errOut := fmt.Errorf("iface name or bpf programs are empty")
		log.Error().Err(errOut)
		return errOut
	}

	c.HostInterfaces, _ = getHostInterfaces()
	if _, ok := c.HostInterfaces[ifaceName]; !ok {
		c.CleanupProgramsOnInterface(ifaceName)
		errOut := fmt.Errorf("%s interface name not found in the host Stop called", ifaceName)
		log.Error().Err(errOut)
		return errOut
	}

	c.Mu.Lock()
	defer c.Mu.Unlock()

	for _, bpfProg := range bpfProgs.XDPIngress {
		if c.IngressXDPBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.IngressXDPBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartXDPRootProgram(ifaceName, models.XDPIngressType); err != nil {
					c.IngressXDPBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain XDP BPF programs: %w", err)
				}
				log.Info().Msgf("Push Back and Start XDP program : %s seq_id : %d", bpfProg.Name, bpfProg.SeqID)
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.XDPIngressType); err != nil {
					return fmt.Errorf("failed to update BPF Program: %w", err)
				}
			}
		} else if err := c.VerifyNUpdateBPFProgram(bpfProg, ifaceName, models.XDPIngressType); err != nil {
			return fmt.Errorf("failed to update xdp BPF Program: %w", err)
		}
	}

	for _, bpfProg := range bpfProgs.TCIngress {
		if c.IngressTCBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.IngressTCBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartTCRootProgram(ifaceName, models.IngressType); err != nil {
					c.IngressTCBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
				}
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.IngressType); err != nil {
					return fmt.Errorf("failed to update BPF Program: %w", err)
				}
			}
		} else if err := c.VerifyNUpdateBPFProgram(bpfProg, ifaceName, models.IngressType); err != nil {
			return fmt.Errorf("failed to update BPF Program: %w", err)
		}
	}

	for _, bpfProg := range bpfProgs.TCEgress {
		if c.EgressTCBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.EgressTCBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartTCRootProgram(ifaceName, models.EgressType); err != nil {
					c.EgressTCBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
				}
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.EgressType); err != nil {
					return fmt.Errorf("failed to update BPF Program: %w", err)
				}
			}
		} else if err := c.VerifyNUpdateBPFProgram(bpfProg, ifaceName, models.EgressType); err != nil {
			return fmt.Errorf("failed to update BPF Program: %w", err)
		}
	}

	for _, bpfProg := range bpfProgs.Probes {
		if err := c.PushBackAndStartProbe(bpfProg); err != nil {
			return fmt.Errorf("failed to update Probe BPF Program: %w", err)
		}
	}
	return nil
}

// DeployeBPFPrograms - Starts eBPF programs on the node if they are not running
func (c *NFConfigs) DeployeBPFPrograms(bpfProgs []models.L3afBPFPrograms) error {
	for _, bpfProg := range bpfProgs {
		if err := c.Deploy(bpfProg.Iface, bpfProg.HostName, bpfProg.BpfPrograms); err != nil {
			if err := c.SaveConfigsToConfigStore(); err != nil {
				return fmt.Errorf("deploy eBPF Programs failed to save configs %w", err)
			}
			return fmt.Errorf("failed to deploy BPF program on iface %s with error: %w", bpfProg.Iface, err)
		}
		if len(c.Ifaces) == 0 {
			c.Ifaces = map[string]string{bpfProg.Iface: bpfProg.Iface}
		} else {
			c.Ifaces[bpfProg.Iface] = bpfProg.Iface
		}
	}

	if err := c.RemoveMissingNetIfacesNBPFProgsInConfig(bpfProgs); err != nil {
		log.Warn().Err(err).Msgf("Remove missing interfaces and BPF programs in the config failed with error ")
	}
	if err := c.SaveConfigsToConfigStore(); err != nil {
		return fmt.Errorf("deploy eBPF Programs failed to save configs %w", err)
	}
	return nil
}

// SaveConfigsToConfigStore - Writes configs to persistent store
func (c *NFConfigs) SaveConfigsToConfigStore() error {

	var bpfProgs []models.L3afBPFPrograms

	c.HostInterfaces, _ = getHostInterfaces()
	for _, iface := range c.Ifaces {
		if _, interfaceFound := c.HostInterfaces[iface]; interfaceFound {
			log.Info().Msgf("SaveConfigsToConfigStore - %s", iface)
			bpfPrograms := c.EBPFPrograms(iface)
			bpfProgs = append(bpfProgs, bpfPrograms)
		}
	}

	file, err := json.MarshalIndent(bpfProgs, "", " ")
	if err != nil {
		log.Error().Err(err).Msgf("failed to marshal configs to save")
		return fmt.Errorf("failed to marshal configs %w", err)
	}
	if err = os.WriteFile(c.HostConfig.L3afConfigStoreFileName, file, 0644); err != nil {
		log.Error().Err(err).Msgf("failed write to file operation")
		return fmt.Errorf("failed to save configs %w", err)
	}

	return nil
}

// EBPFPrograms - Method provides list of eBPF Programs running on iface
func (c *NFConfigs) EBPFPrograms(iface string) models.L3afBPFPrograms {
	BPFProgram := models.L3afBPFPrograms{
		HostName:    c.HostName,
		Iface:       iface,
		BpfPrograms: &models.BPFPrograms{},
	}

	bpfList := c.IngressXDPBpfs[iface]
	if bpfList != nil {
		e := bpfList.Front()
		if c.HostConfig.BpfChainingEnabled && e.Value.(*BPF).Program.Name == c.HostConfig.XDPRootPackageName {
			e = e.Next()
		}
		for ; e != nil; e = e.Next() {
			BPFProgram.BpfPrograms.XDPIngress = append(BPFProgram.BpfPrograms.XDPIngress, &e.Value.(*BPF).Program)
		}
	}
	bpfList = c.IngressTCBpfs[iface]
	if bpfList != nil {
		e := bpfList.Front()
		if c.HostConfig.BpfChainingEnabled && e.Value.(*BPF).Program.Name == c.HostConfig.TCRootPackageName {
			e = e.Next()
		}
		for ; e != nil; e = e.Next() {
			BPFProgram.BpfPrograms.TCIngress = append(BPFProgram.BpfPrograms.TCIngress, &e.Value.(*BPF).Program)
		}
	}
	bpfList = c.EgressTCBpfs[iface]
	if bpfList != nil {
		e := bpfList.Front()
		if c.HostConfig.BpfChainingEnabled && e.Value.(*BPF).Program.Name == c.HostConfig.TCRootPackageName {
			e = e.Next()
		}
		for ; e != nil; e = e.Next() {
			BPFProgram.BpfPrograms.TCEgress = append(BPFProgram.BpfPrograms.TCEgress, &e.Value.(*BPF).Program)
		}
	}

	e := c.ProbesBpfs.Front()
	for ; e != nil; e = e.Next() {
		BPFProgram.BpfPrograms.Probes = append(BPFProgram.BpfPrograms.Probes, &e.Value.(*BPF).Program)
	}

	return BPFProgram
}

// EBPFProgramsAll - Method provides list of eBPF Programs running on all ifaces on the host
func (c *NFConfigs) EBPFProgramsAll() []models.L3afBPFPrograms {

	BPFPrograms := make([]models.L3afBPFPrograms, 0)
	for iface := range c.Ifaces {
		BPFProgram := c.EBPFPrograms(iface)
		BPFPrograms = append(BPFPrograms, BPFProgram)
	}

	return BPFPrograms
}

// RemoveMissingNetIfacesNBPFProgsInConfig - Stops running eBPF programs which are missing in the config
func (c *NFConfigs) RemoveMissingNetIfacesNBPFProgsInConfig(bpfProgCfgs []models.L3afBPFPrograms) error {
	tempIfaces := map[string]bool{}
	wg := sync.WaitGroup{}
	for _, bpfProg := range bpfProgCfgs {
		tempIfaces[bpfProg.Iface] = true
		if ifaceName, ok := c.Ifaces[bpfProg.Iface]; ok {
			_, ok := c.IngressXDPBpfs[ifaceName]
			if ok {
				wg.Add(1)
				go func(bpfProg models.L3afBPFPrograms) {
					defer wg.Done()
					if err := c.RemoveMissingBPFProgramsInConfig(bpfProg, ifaceName, models.XDPIngressType); err != nil {
						log.Error().Err(err).Msgf("Failed to stop missing program for network interface %s direction Ingress", ifaceName)
					}
				}(bpfProg)
			}
			_, ok = c.IngressTCBpfs[ifaceName]
			if ok {
				wg.Add(1)
				go func(bpfProg models.L3afBPFPrograms) {
					defer wg.Done()
					if err := c.RemoveMissingBPFProgramsInConfig(bpfProg, ifaceName, models.IngressType); err != nil {
						log.Error().Err(err).Msgf("Failed to stop missing program for network interface %s direction Ingress", ifaceName)
					}
				}(bpfProg)
			}
			_, ok = c.EgressTCBpfs[ifaceName]
			if ok {
				wg.Add(1)
				go func(bpfProg models.L3afBPFPrograms) {
					defer wg.Done()
					if err := c.RemoveMissingBPFProgramsInConfig(bpfProg, ifaceName, models.EgressType); err != nil {
						log.Error().Err(err).Msgf("Failed to stop missing program for network interface %s direction Ingress", ifaceName)
					}
				}(bpfProg)
			}
		}
	}
	wg.Wait()

	for _, ifaceName := range c.Ifaces {
		if _, ok := tempIfaces[ifaceName]; !ok {
			log.Info().Msgf("Missing Network Interface %s in the configs, stopping", ifaceName)
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.XDPIngressType); err != nil {
				log.Error().Err(err).Msgf("Failed to stop all the program in the direction xdp ingress for interface %s", ifaceName)
			}
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.IngressType); err != nil {
				log.Error().Err(err).Msgf("Failed to stop all the program in the direction tc ingress for interface %s", ifaceName)
			}
			if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.EgressType); err != nil {
				log.Error().Err(err).Msgf("Failed to stop all the program in the direction tc egress for interface %s", ifaceName)
			}
			delete(c.Ifaces, ifaceName)
		}
	}

	return nil
}

// RemoveMissingBPFProgramsInConfig - This method to stop the eBPF programs which are not listed in the config.
func (c *NFConfigs) RemoveMissingBPFProgramsInConfig(bpfProg models.L3afBPFPrograms, ifaceName, direction string) error {
	var bpfProgArr []*models.BPFProgram
	var bpfList *list.List
	switch direction {
	case models.XDPIngressType:
		bpfProgArr = bpfProg.BpfPrograms.XDPIngress
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfProgArr = bpfProg.BpfPrograms.TCIngress
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfProgArr = bpfProg.BpfPrograms.TCEgress
		bpfList = c.EgressTCBpfs[ifaceName]
	default: // we should never reach here
		return fmt.Errorf("unknown direction type %s", direction)
	}

	if bpfList == nil {
		// Empty list, Nothing to check return
		return nil
	}

	e := bpfList.Front()
	if e != nil && c.HostConfig.BpfChainingEnabled {
		e = e.Next()
	}
	for ; e != nil; e = e.Next() {
		prog := e.Value.(*BPF)
		Found := false
		for _, bpfConfigProg := range bpfProgArr {
			if bpfConfigProg.Name == prog.Program.Name {
				Found = true
				break
			}
		}
		if !Found {
			log.Info().Msgf("eBPF Program not found in config stopping - %s direction %s", prog.Program.Name, direction)
			prog.Program.AdminStatus = models.Disabled
			if err := prog.Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
				return fmt.Errorf("failed to stop to on removed config BPF %s iface %s direction %s with err %w", prog.Program.Name, ifaceName, models.XDPIngressType, err)
			}
			tmpNextBPF := e.Next()
			tmpPreviousBPF := e.Prev()
			bpfList.Remove(e)
			if tmpNextBPF != nil && tmpNextBPF.Prev() != nil { // relink the next element
				if err := c.LinkBPFPrograms(tmpNextBPF.Prev().Value.(*BPF), tmpNextBPF.Value.(*BPF)); err != nil {
					log.Error().Err(err).Msgf("missing config - failed LinkBPFPrograms")
					return fmt.Errorf("missing config - failed LinkBPFPrograms %w", err)
				}
			}
			// Check if list contains root program only then stop the root program.
			if tmpPreviousBPF.Prev() == nil && tmpPreviousBPF.Next() == nil {
				log.Info().Msgf("no eBPF Programs are running, stopping root program")

				if err := c.StopRootProgram(ifaceName, direction); err != nil {
					return fmt.Errorf("failed to stop to root program of iface %s direction XDP Ingress with err %w", ifaceName, err)
				}
			}
		}
	}
	return nil
}

// getHostInterfaces - return host network interfaces
func getHostInterfaces() (map[string]bool, error) {
	var hostIfaces = make(map[string]bool, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get net interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		hostIfaces[iface.Name] = true
	}
	return hostIfaces, nil
}

func (c *NFConfigs) AddAndStartBPF(bpfProg *models.BPFProgram, ifaceName string, direction string) error {
	var bpfList *list.List
	if bpfProg == nil {
		return fmt.Errorf("AddAndStartBPF - bpf program is nil")
	}

	if bpfProg.AdminStatus == models.Disabled {
		return nil
	}

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if data.Program.Name == bpfProg.Name {
			log.Warn().Msgf("%v is already running on %v iface and in %v direction ", data.Program.Name, ifaceName, direction)
			return nil
		}

		if data.Program.SeqID == bpfProg.SeqID {
			log.Warn().Msgf("duplicate seq Id detected for %v in direction %v", data.Program.Name, direction)
			return nil
		}
	}
	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if data.Program.SeqID > bpfProg.SeqID {
			bpf := NewBpfProgram(c.Ctx, *bpfProg, c.HostConfig, ifaceName)
			tmpBPF := bpfList.InsertBefore(bpf, e)
			if err := c.DownloadAndStartBPFProgram(tmpBPF, ifaceName, direction); err != nil {
				return fmt.Errorf("failed to download and start eBPF program %s version %s iface %s direction %s with err %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
			}

			if tmpBPF.Next() != nil {
				if err := c.LinkBPFPrograms(tmpBPF.Value.(*BPF), tmpBPF.Next().Value.(*BPF)); err != nil {
					log.Error().Err(err).Msg("AddAndStartBPF - failed LinkBPFPrograms after InsertBefore element to with next prog")
					return fmt.Errorf("AddAndStartBPFProg - failed LinkBPFPrograms after InsertBefore element to with next prog %w", err)
				}
			}
			return nil
		}
	}

	// insert at the end
	if err := c.PushBackAndStartBPF(bpfProg, ifaceName, direction); err != nil {
		return fmt.Errorf("failed to push back and start eBPF Program %s version %s iface %s direction %s with err %w", bpfProg.Name, bpfProg.Version, ifaceName, direction, err)
	}

	return nil
}

// AddProgramWithoutChaining : add eBPF program on given interface when chaining is not enabled
func (c *NFConfigs) AddProgramWithoutChaining(ifaceName string, bpfProgs *models.BPFPrograms) error {
	if c.HostConfig.BpfChainingEnabled {
		return nil
	}

	if len(bpfProgs.XDPIngress) > 1 || len(bpfProgs.TCIngress) > 1 || len(bpfProgs.TCEgress) > 1 {
		return fmt.Errorf("failed to add multiple programs because chaining is disabled")
	}

	if len(bpfProgs.XDPIngress) == 1 {
		bpfProg := bpfProgs.XDPIngress[0]
		if bpfProg.AdminStatus == models.Enabled {
			if c.IngressXDPBpfs[ifaceName] == nil {
				c.IngressXDPBpfs[ifaceName] = list.New()
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.XDPIngressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			} else {
				prog := c.IngressXDPBpfs[ifaceName].Front().Value.(*BPF)
				return fmt.Errorf("failed to add %v due to existing program %v on iface %v direction %v", bpfProg.Name, prog.Program.Name, ifaceName, models.XDPIngressType)
			}
		}
	}

	if len(bpfProgs.TCIngress) == 1 {
		bpfProg := bpfProgs.TCIngress[0]
		if bpfProg.AdminStatus == models.Enabled {
			if c.IngressTCBpfs[ifaceName] == nil {
				c.IngressTCBpfs[ifaceName] = list.New()
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.IngressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			} else {
				prog := c.IngressTCBpfs[ifaceName].Front().Value.(*BPF)
				return fmt.Errorf("failed to add %v due to existing program %v on iface %v direction %v", bpfProg.Name, prog.Program.Name, ifaceName, models.IngressType)
			}
		}
	}

	if len(bpfProgs.TCEgress) == 1 {
		bpfProg := bpfProgs.TCEgress[0]
		if bpfProg.AdminStatus == models.Enabled {
			if c.EgressTCBpfs[ifaceName] == nil {
				c.EgressTCBpfs[ifaceName] = list.New()
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.EgressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			} else {
				prog := c.EgressTCBpfs[ifaceName].Front().Value.(*BPF)
				return fmt.Errorf("failed to add %v due to existing program %v on iface %v direction %v", bpfProg.Name, prog.Program.Name, ifaceName, models.EgressType)
			}
		}
	}

	return nil
}

// AddProgramsOnInterface will add given ebpf programs on given interface
func (c *NFConfigs) AddProgramsOnInterface(ifaceName, HostName string, bpfProgs *models.BPFPrograms) error {

	if HostName != c.HostName {
		errOut := fmt.Errorf("provided bpf programs do not belong to this host")
		log.Error().Err(errOut)
		return errOut
	}

	if ifaceName == "" || bpfProgs == nil {
		errOut := fmt.Errorf("iface name or bpf programs are empty")
		log.Error().Err(errOut)
		return errOut
	}

	c.HostInterfaces, _ = getHostInterfaces()
	if _, ok := c.HostInterfaces[ifaceName]; !ok {
		errOut := fmt.Errorf("%s interface name not found in the host", ifaceName)
		log.Error().Err(errOut)
		return errOut
	}

	c.Mu.Lock()
	defer c.Mu.Unlock()

	if !c.HostConfig.BpfChainingEnabled {
		errout := c.AddProgramWithoutChaining(ifaceName, bpfProgs)
		if errout != nil {
			return errout
		}
		return nil
	}

	for _, bpfProg := range bpfProgs.XDPIngress {
		if c.IngressXDPBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.IngressXDPBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartXDPRootProgram(ifaceName, models.XDPIngressType); err != nil {
					c.IngressXDPBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain XDP BPF programs: %w", err)
				}

				log.Info().Msgf("Push Back and Start XDP program : %s seq_id : %d", bpfProg.Name, bpfProg.SeqID)
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.XDPIngressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			}
		} else if err := c.AddAndStartBPF(bpfProg, ifaceName, models.XDPIngressType); err != nil {
			return fmt.Errorf("failed to AddAndStartBPF xdp BPF Program: %w", err)
		}
	}

	for _, bpfProg := range bpfProgs.TCIngress {
		if c.IngressTCBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.IngressTCBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartTCRootProgram(ifaceName, models.IngressType); err != nil {
					c.IngressTCBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
				}

				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.IngressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			}
		} else if err := c.AddAndStartBPF(bpfProg, ifaceName, models.IngressType); err != nil {
			return fmt.Errorf("failed to AddAndStartBPF tcingress BPF Program: %w", err)
		}
	}

	for _, bpfProg := range bpfProgs.TCEgress {
		if c.EgressTCBpfs[ifaceName] == nil {
			if bpfProg.AdminStatus == models.Enabled {
				c.EgressTCBpfs[ifaceName] = list.New()
				if err := c.VerifyAndStartTCRootProgram(ifaceName, models.EgressType); err != nil {
					c.EgressTCBpfs[ifaceName] = nil
					return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
				}
				if err := c.PushBackAndStartBPF(bpfProg, ifaceName, models.EgressType); err != nil {
					return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
				}
			}
		} else if err := c.AddAndStartBPF(bpfProg, ifaceName, models.EgressType); err != nil {
			return fmt.Errorf("failed to AddAndStartBPF tcegress BPF Program: %w", err)
		}
	}

	return nil
}

// AddeBPFPrograms - Starts eBPF programs on the node if they are not running
func (c *NFConfigs) AddeBPFPrograms(bpfProgs []models.L3afBPFPrograms) error {
	for _, bpfProg := range bpfProgs {
		if err := c.AddProgramsOnInterface(bpfProg.Iface, bpfProg.HostName, bpfProg.BpfPrograms); err != nil {
			if err := c.SaveConfigsToConfigStore(); err != nil {
				return fmt.Errorf("add eBPF Programs failed to save configs %w", err)
			}
			return fmt.Errorf("failed to Add BPF program on iface %s with error: %w", bpfProg.Iface, err)
		}
		if err := c.AddProbePrograms(bpfProg.HostName, bpfProg.BpfPrograms.Probes); err != nil {
			if err := c.SaveConfigsToConfigStore(); err != nil {
				return fmt.Errorf("add eBPF Programs of type probes failed to save configs %w", err)
			}
			return fmt.Errorf("failed to Add eBPF program of type probe with error: %w", err)
		}
		c.Ifaces = map[string]string{bpfProg.Iface: bpfProg.Iface}
		if len(c.Ifaces) == 0 {
			c.Ifaces = map[string]string{bpfProg.Iface: bpfProg.Iface}
		} else {
			c.Ifaces[bpfProg.Iface] = bpfProg.Iface
		}
	}
	if err := c.SaveConfigsToConfigStore(); err != nil {
		return fmt.Errorf("AddeBPFPrograms failed to save configs %w", err)
	}
	return nil
}

// CleanupProgramsOnInterface removes all EBPF program and its metadata, on the network interface provided
func (c *NFConfigs) CleanupProgramsOnInterface(ifaceName string) {
	if c.IngressXDPBpfs[ifaceName] != nil {
		if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.XDPIngressType); err != nil {
			log.Warn().Err(err).Msg("failed to Close Ingress XDP BPF Program")
		}
	}
	if c.IngressTCBpfs[ifaceName] != nil {
		if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.IngressType); err != nil {
			log.Warn().Err(err).Msg("failed to Close Ingress XDP BPF Program")
		}
	}
	if c.EgressTCBpfs[ifaceName] != nil {
		if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.EgressType); err != nil {
			log.Warn().Err(err).Msg("failed to Close Ingress XDP BPF Program")
		}
	}
}

// DeleteProgramsOnInterface : It will delete ebpf Programs on the given interface
func (c *NFConfigs) DeleteProgramsOnInterface(ifaceName, HostName string, bpfProgs *models.BPFProgramNames) error {
	var err error
	if c.HostInterfaces, err = getHostInterfaces(); err != nil {
		errOut := fmt.Errorf("failed get interfaces in DeleteProgramsOnInterface Function: %v", err)
		log.Error().Err(errOut)
		return errOut
	}

	if HostName != c.HostName {
		errOut := fmt.Errorf("provided bpf programs do not belong to this host")
		log.Error().Err(errOut)
		return errOut
	}

	if ifaceName == "" || bpfProgs == nil {
		errOut := fmt.Errorf("iface name or bpf programs are empty")
		log.Error().Err(errOut)
		return errOut
	}

	if _, ok := c.HostInterfaces[ifaceName]; !ok {
		c.CleanupProgramsOnInterface(ifaceName)
		errOut := fmt.Errorf("%s interface name not found in the host, Stop called, %w", ifaceName, err)
		log.Error().Err(errOut)
		return errOut
	}

	c.Mu.Lock()
	defer c.Mu.Unlock()

	sort.Strings(bpfProgs.XDPIngress)
	if c.IngressXDPBpfs[ifaceName] != nil {
		bpfList := c.IngressXDPBpfs[ifaceName]
		for e := bpfList.Front(); e != nil; {
			next := e.Next()
			data := e.Value.(*BPF)
			if BinarySearch(bpfProgs.XDPIngress, data.Program.Name) {
				err := c.DeleteProgramsOnInterfaceHelper(e, ifaceName, models.XDPIngressType, bpfList)
				if err != nil {
					return fmt.Errorf("DeleteProgramsOnInterfaceHelper function failed : %w", err)
				}
			}
			e = next
		}
		if bpfList.Len() == 0 {
			c.IngressXDPBpfs[ifaceName] = nil
		}
	}
	sort.Strings(bpfProgs.TCIngress)
	if c.IngressTCBpfs[ifaceName] != nil {
		bpfList := c.IngressTCBpfs[ifaceName]
		for e := bpfList.Front(); e != nil; {
			next := e.Next()
			data := e.Value.(*BPF)
			if BinarySearch(bpfProgs.TCIngress, data.Program.Name) {
				err := c.DeleteProgramsOnInterfaceHelper(e, ifaceName, models.IngressType, bpfList)
				if err != nil {
					return fmt.Errorf("DeleteProgramsOnInterfaceHelper function failed : %w", err)
				}
			}
			e = next
		}
		if bpfList.Len() == 0 {
			c.IngressTCBpfs[ifaceName] = nil
		}
	}

	sort.Strings(bpfProgs.TCEgress)
	if c.EgressTCBpfs[ifaceName] != nil {
		bpfList := c.EgressTCBpfs[ifaceName]
		for e := bpfList.Front(); e != nil; {
			next := e.Next()
			data := e.Value.(*BPF)
			if BinarySearch(bpfProgs.TCEgress, data.Program.Name) {
				err := c.DeleteProgramsOnInterfaceHelper(e, ifaceName, models.EgressType, bpfList)
				if err != nil {
					return fmt.Errorf("DeleteProgramsOnInterfaceHelper function failed : %w", err)
				}
			}
			e = next
		}
		if bpfList.Len() == 0 {
			c.EgressTCBpfs[ifaceName] = nil
		}
	}

	sort.Strings(bpfProgs.Probes)
	for e := c.ProbesBpfs.Front(); e != nil; {
		next := e.Next()
		data := e.Value.(*BPF)
		if BinarySearch(bpfProgs.Probes, data.Program.Name) {
			err := c.DeleteProgramsOnInterfaceHelper(e, ifaceName, "", &c.ProbesBpfs)
			if err != nil {
				return fmt.Errorf("DeleteProgramsOnInterfaceHelper function failed : %w", err)
			}
		}
		e = next
	}
	return nil
}

// DeleteProgramsOnInterfaceHelper : helper function for DeleteProgramsOnInterface function
func (c *NFConfigs) DeleteProgramsOnInterfaceHelper(e *list.Element, ifaceName string, direction string, bpfList *list.List) error {
	if e == nil {
		return nil
	}
	prog := e.Value.(*BPF)
	prog.Program.AdminStatus = models.Disabled
	if err := prog.Stop(ifaceName, direction, c.HostConfig.BpfChainingEnabled); err != nil {
		return fmt.Errorf("failed to stop %s iface %s direction %s with err %w", prog.Program.Name, ifaceName, direction, err)
	}
	tmpNextBPF := e.Next()
	tmpPreviousBPF := e.Prev()
	bpfList.Remove(e)

	if !c.HostConfig.BpfChainingEnabled {
		return nil
	}
	if tmpNextBPF != nil && tmpNextBPF.Prev() != nil { // relink the next element
		if err := c.LinkBPFPrograms(tmpNextBPF.Prev().Value.(*BPF), tmpNextBPF.Value.(*BPF)); err != nil {
			log.Error().Err(err).Msgf("DeleteProgramsOnInterfaceHelper - failed LinkBPFPrograms")
			return fmt.Errorf("DeleteProgramsOnInterfaceHelper - failed LinkBPFPrograms %w", err)
		}
	}
	// Check if list contains root program only then stop the root program.
	if tmpPreviousBPF.Prev() == nil && tmpPreviousBPF.Next() == nil {
		log.Info().Msgf("no ebpf programs are running, stopping root program")

		if err := c.StopRootProgram(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to stop to root program of iface %s direction %v with err %w", ifaceName, direction, err)
		}
	}
	return nil
}

// DeleteEbpfPrograms - Delete eBPF programs on the node if they are running
func (c *NFConfigs) DeleteEbpfPrograms(bpfProgs []models.L3afBPFProgramNames) error {
	for _, bpfProg := range bpfProgs {
		if err := c.DeleteProgramsOnInterface(bpfProg.Iface, bpfProg.HostName, bpfProg.BpfProgramNames); err != nil {
			if err := c.SaveConfigsToConfigStore(); err != nil {
				return fmt.Errorf("SaveConfigsToConfigStore failed to save configs %w", err)
			}
			return fmt.Errorf("failed to Remove eBPF program on iface %s with error: %w", bpfProg.Iface, err)
		}
		c.Ifaces = map[string]string{bpfProg.Iface: bpfProg.Iface}
	}
	if err := c.SaveConfigsToConfigStore(); err != nil {
		return fmt.Errorf("DeleteEbpfPrograms failed to save configs %w", err)
	}
	return nil
}

// BinarySearch: It is checking a target string exists in sorted slice of strings
func BinarySearch(names []string, target string) bool {
	left := 0
	right := len(names) - 1

	for right >= left {
		mid := (left + right) >> 1
		if names[mid] == target {
			return true
		} else if names[mid] > target {
			right = mid - 1
		} else {
			left = mid + 1
		}
	}
	return false
}

func (c *NFConfigs) AddProbePrograms(HostName string, bpfProgs []*models.BPFProgram) error {
	if HostName != c.HostName {
		errOut := fmt.Errorf("provided bpf programs do not belong to this host")
		log.Error().Err(errOut)
		return errOut
	}

	if len(bpfProgs) == 0 {
		return nil
	}

	for _, bpfProg := range bpfProgs {
		if err := c.PushBackAndStartProbe(bpfProg); err != nil {
			return fmt.Errorf("failed to PushBackAndStartBPF BPF Program: %w", err)
		}
	}

	return nil
}

// PushBackAndStartProbe method inserts the element at the end of the list
func (c *NFConfigs) PushBackAndStartProbe(bpfProg *models.BPFProgram) error {
	log.Info().Msgf("PushBackAndStartProbe: %s", bpfProg.Name)
	bpf := NewBpfProgram(c.Ctx, *bpfProg, c.HostConfig, "")

	if err := c.DownloadAndStartProbes(c.ProbesBpfs.PushBack(bpf)); err != nil {
		return fmt.Errorf("failed to download and start the BPF %s  with err: %w", bpfProg.Name, err)
	}

	return nil
}

func (c *NFConfigs) DownloadAndStartProbes(element *list.Element) error {
	if element == nil {
		return fmt.Errorf("element is nil pointer")
	}

	bpf := element.Value.(*BPF)

	if err := bpf.VerifyAndGetArtifacts(c.HostConfig); err != nil {
		return fmt.Errorf("failed to get artifacts %s with error: %w", bpf.Program.Artifact, err)
	}

	if err := bpf.LoadBPFProgram(""); err != nil {
		return fmt.Errorf("failed to load bpf program %s with error: %w", bpf.Program.Name, err)
	}

	return nil
}

func SerilazeProgram(e *list.Element) *models.L3AFMetaData {
	tmp := &models.L3AFMetaData{}
	bpf := e.Value.(*BPF)
	tmp.BpfMaps = make([]string, 0)
	for _, v := range bpf.BpfMaps {
		tmp.BpfMaps = append(tmp.BpfMaps, v.Name)
	}
	tmp.FilePath = bpf.FilePath
	tmp.MapNamePath = bpf.MapNamePath
	tmp.PrevMapNamePath = bpf.PrevMapNamePath
	tmp.PrevProgMapID = uint32(bpf.PrevProgMapID)
	tmp.ProgID = uint32(bpf.ProgID)
	tmp.Program = bpf.Program
	tmp.ProgMapID = uint32(bpf.ProgMapID)
	tmp.RestartCount = bpf.RestartCount
	if bpf.Cmd != nil {
		tmp.UserProgramPID = bpf.Cmd.Process.Pid
	}
	tmp.ProgMapCollection = models.MetaColl{
		Programs: make([]string, 0),
		Maps:     make([]string, 0),
	}
	for k, _ := range bpf.ProgMapCollection.Programs {
		tmp.ProgMapCollection.Programs = append(tmp.ProgMapCollection.Programs, k)
	}
	for k, _ := range bpf.ProgMapCollection.Maps {
		tmp.ProgMapCollection.Maps = append(tmp.ProgMapCollection.Maps, k)
	}
	tmp.MetricsBpfMaps = make(map[string]models.MetaMetricsBPFMap)
	for k1, v1 := range bpf.MetricsBpfMaps {
		values := make([]float64, 0)
		tmpval := v1.Values
		for i := 0; i < v1.Values.Len(); i++ {
			if tmpval.Value != nil {
				values = append(values, tmpval.Value.(float64))
			}
			tmpval = tmpval.Next()
		}
		tmp.MetricsBpfMaps[k1] = models.MetaMetricsBPFMap{
			MapName:    v1.Name,
			Key:        v1.Key,
			Values:     values,
			Aggregator: v1.Aggregator,
			LastValue:  float64(v1.LastValue),
		}
	}
	tmp.XDPLink = false
	if bpf.XDPLink != nil {
		tmp.XDPLink = true
	}
	return tmp
}

func (c *NFConfigs) GetL3AFHOSTDATA() models.L3AFALLHOSTDATA {
	result := models.L3AFALLHOSTDATA{}
	result.HostName = c.HostName
	result.Ifaces = c.Ifaces
	result.HostInterfaces = c.HostInterfaces
	result.IngressXDPBpfs = make(map[string][]*models.L3AFMetaData)
	result.IngressTCBpfs = make(map[string][]*models.L3AFMetaData)
	result.EgressTCBpfs = make(map[string][]*models.L3AFMetaData)
	result.ProbesBpfs = make([]models.L3AFMetaData, 0)
	for k, v := range c.IngressXDPBpfs {
		ls := make([]*models.L3AFMetaData, 0)
		for e := v.Front(); e != nil; e = e.Next() {
			ls = append(ls, SerilazeProgram(e))
		}
		result.IngressXDPBpfs[k] = ls
	}
	for k, v := range c.IngressTCBpfs {
		ls := make([]*models.L3AFMetaData, 0)
		for e := v.Front(); e != nil; e = e.Next() {
			ls = append(ls, SerilazeProgram(e))
		}
		result.IngressTCBpfs[k] = ls
	}
	for k, v := range c.EgressTCBpfs {
		ls := make([]*models.L3AFMetaData, 0)
		for e := v.Front(); e != nil; e = e.Next() {
			ls = append(ls, SerilazeProgram(e))
		}
		result.EgressTCBpfs[k] = ls
	}
	for e := c.ProbesBpfs.Front(); e != nil; e = e.Next() {
		result.ProbesBpfs = append(result.ProbesBpfs, *SerilazeProgram(e))
	}

	metrics, _ := prometheus.DefaultGatherer.Gather()
	result.AllStats = make([]models.MetricVec, 0)
	listofMetrics := []string{"l3afd_BPFStartCount", "l3afd_BPFStopCount", "l3afd_BPFUpdateCount", "l3afd_BPFUpdateFailedCount", "l3afd_BPFRunning", "l3afd_BPFStartTime", "l3afd_BPFMonitorMap"}
	for _, metric := range metrics {
		name := *metric.Name
		tp := metric.Type.Number()
		if slices.Index(listofMetrics, name) != -1 {
			for _, m := range metric.Metric {
				r := models.MetricVec{}
				lt := m.GetLabel()
				for _, y := range lt {
					r.Labels = append(r.Labels, models.Label{
						Name:  *y.Name,
						Value: *y.Value,
					})
				}
				r.MetricName = name
				r.Type = int32(tp)
				if r.Type == 0 {
					r.Value = m.GetCounter().GetValue()
				} else {
					r.Value = m.Gauge.GetValue()
				}
				result.AllStats = append(result.AllStats, r)
			}
		}
	}
	return result
}

func (c *NFConfigs) StartAllUserProgramsAndProbes(t models.L3AFALLHOSTDATA) error {
	for iface, v := range c.IngressXDPBpfs {
		l := t.IngressXDPBpfs[iface]
		for e, idx := v.Front(), 0; e != nil; e, idx = e.Next(), idx+1 {
			// Starting Probes
			b := e.Value.(*BPF)
			if err := b.LoadBPFProgram(iface); err != nil {
				return fmt.Errorf("not able to load probes %w", err)
			}
			if l[idx].UserProgramPID > 0 {
				// Stopping User Program
				process, err := os.FindProcess(l[idx].UserProgramPID)
				if err != nil {
					log.Warn().Msgf("user program is not running for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				err = process.Signal(syscall.SIGTERM)
				if err != nil {
					log.Warn().Msgf("failed to stop userprogram for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				// Starting User Program
				if err := b.StartUserProgram(iface, models.XDPIngressType, c.HostConfig.BpfChainingEnabled); err != nil {
					return err
				}
			}
		}
	}

	for iface, v := range c.IngressTCBpfs {
		l := t.IngressTCBpfs[iface]
		for e, idx := v.Front(), 0; e != nil; e, idx = e.Next(), idx+1 {
			b := e.Value.(*BPF)
			ef := b.Program.EntryFunctionName
			b.Program.EntryFunctionName = ""
			if err := b.LoadBPFProgram(iface); err != nil {
				return fmt.Errorf("not able to load probes %w", err)
			}
			b.Program.EntryFunctionName = ef
			if l[idx].UserProgramPID > 0 {
				// Stopping User Program
				process, err := os.FindProcess(l[idx].UserProgramPID)
				if err != nil {
					log.Warn().Msgf("user program is not running for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				err = process.Signal(syscall.SIGTERM)
				if err != nil {
					log.Warn().Msgf("failed to stop userprogram for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				// Starting User Program
				if err := b.StartUserProgram(iface, models.XDPIngressType, c.HostConfig.BpfChainingEnabled); err != nil {
					return err
				}
			}
		}
	}

	for iface, v := range c.EgressTCBpfs {
		l := t.EgressTCBpfs[iface]
		for e, idx := v.Front(), 0; e != nil; e, idx = e.Next(), idx+1 {
			b := e.Value.(*BPF)
			ef := b.Program.EntryFunctionName
			b.Program.EntryFunctionName = ""
			if err := b.LoadBPFProgram(iface); err != nil {
				return fmt.Errorf("not able to load probes %w", err)
			}
			b.Program.EntryFunctionName = ef
			if l[idx].UserProgramPID > 0 {
				// Stopping User Program
				process, err := os.FindProcess(l[idx].UserProgramPID)
				if err != nil {
					log.Warn().Msgf("user program is not running for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				err = process.Signal(syscall.SIGTERM)
				if err != nil {
					log.Warn().Msgf("failed to stop userprogram for %v in direction %v", l[idx].Program.MapName, l[idx].Program.ProgType)
					continue
				}
				// Starting User Program
				if err := b.StartUserProgram(iface, models.XDPIngressType, c.HostConfig.BpfChainingEnabled); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
