// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package bpfprogs provides primitives for NF process monitoring.
package bpfprogs

import (
	"container/list"
	"time"

	"github.com/l3af-project/l3afd/v2/models"

	"github.com/rs/zerolog/log"
)

type BpfMetrics struct {
	Chain     bool
	Intervals int
}

func NewpBpfMetrics(chain bool, interval int) *BpfMetrics {
	m := &BpfMetrics{
		Chain:     chain,
		Intervals: interval,
	}
	return m
}

func (c *BpfMetrics) BpfMetricsStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List, probes *list.List) {
	go c.BpfMetricsWorker(xdpProgs)
	go c.BpfMetricsWorker(ingressTCProgs)
	go c.BpfMetricsWorker(egressTCProgs)
	go c.BpfMetricsProbeWorker(probes)
}

func (c *BpfMetrics) BpfMetricsWorker(bpfProgs map[string]*list.List) {
	for range time.NewTicker(1 * time.Second).C {
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
				if err := bpf.MonitorMaps(ifaceName, c.Intervals); err != nil {
					log.Error().Err(err).Msgf("pMonitor monitor maps failed - %s", bpf.Program.Name)
				}
			}
		}
	}
}

func (c *BpfMetrics) BpfMetricsProbeWorker(bpfProgs *list.List) {
	for range time.NewTicker(1 * time.Second).C {
		if bpfProgs == nil {
			time.Sleep(time.Second)
			continue
		}
		for e := bpfProgs.Front(); e != nil; e = e.Next() {
			bpf := e.Value.(*BPF)
			if bpf.Program.AdminStatus == models.Disabled {
				continue
			}
			if err := bpf.MonitorMaps("", c.Intervals); err != nil {
				log.Error().Err(err).Msgf("pMonitor probe monitor maps failed - %s", bpf.Program.Name)
			}
		}
	}
}
