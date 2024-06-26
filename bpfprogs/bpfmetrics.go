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

type bpfMetrics struct {
	Chain     bool
	Intervals int
}

func NewpBPFMetrics(chain bool, interval int) *bpfMetrics {
	m := &bpfMetrics{
		Chain:     chain,
		Intervals: interval,
	}
	return m
}

func (c *bpfMetrics) bpfMetricsStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List, probes *list.List) {
	go c.bpfMetricsWorker(xdpProgs)
	go c.bpfMetricsWorker(ingressTCProgs)
	go c.bpfMetricsWorker(egressTCProgs)
	go c.BPFMetricsProbeWorker(probes)
}

func (c *bpfMetrics) bpfMetricsWorker(bpfProgs map[string]*list.List) {
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

func (c *bpfMetrics) BPFMetricsProbeWorker(bpfProgs *list.List) {
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
