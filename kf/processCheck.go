// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for BPF process monitoring.
package kf

import (
	"container/list"
	"time"

	"github.com/l3af-project/l3afd/models"
	"github.com/l3af-project/l3afd/stats"

	"github.com/rs/zerolog/log"
)

type pCheck struct {
	MaxRetryCount     int
	Chain             bool
	retryMonitorDelay time.Duration
}

func NewpCheck(rc int, chain bool, interval time.Duration) *pCheck {
	c := &pCheck{
		MaxRetryCount:     rc,
		Chain:             chain,
		retryMonitorDelay: interval,
	}
	return c
}

func (c *pCheck) pCheckStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List) {
	go c.pMonitorWorker(xdpProgs, models.XDPIngressType)
	go c.pMonitorWorker(ingressTCProgs, models.IngressType)
	go c.pMonitorWorker(egressTCProgs, models.EgressType)
}

func (c *pCheck) pMonitorWorker(bpfProgs map[string]*list.List, direction string) {
	for range time.NewTicker(c.retryMonitorDelay).C {
		for ifaceName, bpfList := range bpfProgs {
			if bpfList == nil { // no bpf programs are running
				continue
			}
			for e := bpfList.Front(); e != nil; e = e.Next() {
				bpf := e.Value.(*BPF)
				if c.Chain && bpf.Program.SeqID == 0 { // do not monitor root program
					continue
				}
				if bpf.Program.AdminStatus == models.Disabled {
					continue
				}
				userProgram, bpfProgram, _ := bpf.isRunning()
				if userProgram && bpfProgram {
					stats.SetWithVersion(1.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, direction, ifaceName)
					continue
				}
				// Not running trying to restart
				if bpf.RestartCount < c.MaxRetryCount && bpf.Program.AdminStatus == models.Enabled {
					bpf.RestartCount++
					log.Warn().Msgf("pMonitor BPF Program is not running. Restart attempt: %d, program name: %s, iface: %s",
						bpf.RestartCount, bpf.Program.Name, ifaceName)
					//  User program is a daemon and not running, but the BPF program is loaded
					if !userProgram && bpfProgram {
						if err := bpf.StartUserProgram(ifaceName, direction, c.Chain); err != nil {
							log.Error().Err(err).Msgf("pMonitorWorker: BPF Program start user program failed for program %s", bpf.Program.Name)
						}
					}
					// BPF program is not loaded.
					// if user program is daemon then stop it and restart both the programs
					if !bpfProgram {
						log.Warn().Msgf("%s BPF program is not loaded, %s program reloading ...", bpf.Program.EntryFunctionName, bpf.Program.Name)
						// User program is a daemon and running, stop before reloading the BPF program
						if bpf.Program.UserProgramDaemon && userProgram {
							if err := bpf.Stop(ifaceName, direction, c.Chain); err != nil {
								log.Error().Err(err).Msgf("pMonitorWorker: BPF Program stop failed for program %s", bpf.Program.Name)
							}
						}
						if err := bpf.Start(ifaceName, direction, c.Chain); err != nil {
							log.Error().Err(err).Msgf("pMonitorWorker: BPF Program start failed for program %s", bpf.Program.Name)
						}
					}
				} else {
					stats.SetWithVersion(0.0, stats.BPFRunning, bpf.Program.Name, bpf.Program.Version, direction, ifaceName)
				}
			}
		}
	}
}
