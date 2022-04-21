// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for NF process monitoring.
package kf

import (
	"container/list"
	"time"

	"github.com/l3af-project/l3afd/models"

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

func (c *kfMetrics) kfMetricsStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List) {
	go c.kfMetricsWorker(xdpProgs, models.XDPIngressType)
	go c.kfMetricsWorker(ingressTCProgs, models.IngressType)
	go c.kfMetricsWorker(egressTCProgs, models.EgressType)
}

func (c *kfMetrics) kfMetricsWorker(bpfProgs map[string]*list.List, direction string) {
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
