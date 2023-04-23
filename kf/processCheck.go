// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for NF process monitoring.
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
				bpf := e.Value.(models.BPF)
				if c.Chain && bpf.SeqId() == 0 { // do not monitor root program
					continue
				}
				if bpf.AdminStatus() == models.Disabled {
					continue
				}
				isRunning, _ := bpf.IsRunning()
				if isRunning {
					stats.SetWithVersion(1.0, stats.NFRunning, bpf.Name(), bpf.Version(), direction, ifaceName)
					continue
				}
				// Not running trying to restart
				if bpf.GetRestartCount() < c.MaxRetryCount && bpf.AdminStatus() == models.Enabled {
					bpf.AddToRestartCount(1)
					log.Warn().Msgf("pMonitor BPF Program is not running. Restart attempt: %d, program name: %s, iface: %s",
						bpf.GetRestartCount(), bpf.Name(), ifaceName)
					if err := bpf.Start(ifaceName, direction, c.Chain); err != nil {
						log.Error().Err(err).Msgf("pMonitor BPF Program start failed for program %s", bpf.Name())
					}
				} else {
					stats.SetWithVersion(0.0, stats.NFRunning, bpf.Name(), bpf.Version(), direction, ifaceName)
				}
			}
		}
	}
}
