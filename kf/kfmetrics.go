// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for NF process monitoring.
package kf

import (
	"container/list"
	"time"

	"github.com/l3af-project/l3afd/v2/models"

	"github.com/rs/zerolog/log"
)

type kfMetrics struct {
	Chain     bool
	Intervals int
}

func NewpKFMetrics(chain bool, interval int) *kfMetrics {
	m := &kfMetrics{
		Chain:     chain,
		Intervals: interval,
	}
	return m
}

func (c *kfMetrics) kfMetricsStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List, probes *list.List) {
	go c.kfMetricsWorker(xdpProgs)
	go c.kfMetricsWorker(ingressTCProgs)
	go c.kfMetricsWorker(egressTCProgs)
	go c.kfMetricsProbeWorker(probes)
}

func (c *kfMetrics) kfMetricsWorker(bpfProgs map[string]*list.List) {
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

func (c *kfMetrics) kfMetricsProbeWorker(bpfProgs *list.List) {
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
