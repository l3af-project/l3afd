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

func (c *bpfMetrics) bpfMetricsStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List) {
	go c.bpfMetricsWorker(xdpProgs, models.XDPIngressType)
	go c.bpfMetricsWorker(ingressTCProgs, models.IngressType)
	go c.bpfMetricsWorker(egressTCProgs, models.EgressType)
}

func (c *bpfMetrics) bpfMetricsWorker(bpfProgs map[string]*list.List, direction string) {
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
