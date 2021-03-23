// Package db provides primitives for NF process monitoring.
package db

import (
	"container/list"
	"time"

	"tbd/admind/models"
	"tbd/go-shared/logs"

	"tbd/l3afd/stats"
)

type pCheck struct {
	MaxRetryCount int
	Chain      bool
}

func NewpCheck(rc int, chain bool) *pCheck {
	c := &pCheck{
		MaxRetryCount: rc,
		Chain:      chain,
	}
	return c
}

func (c *pCheck) pCheckStart(xdpProgs, ingressTCProgs, egressTCProgs map[string]*list.List) {
	go c.pMonitorWorker(xdpProgs, models.XDPIngressType)
	go c.pMonitorWorker(ingressTCProgs, models.IngressType)
	go c.pMonitorWorker(egressTCProgs, models.EgressType)
	return
}

func (c *pCheck) pMonitorWorker(bpfProgs map[string]*list.List, direction string) {
	var retryMonitorDelay = time.Second * 30
	for range time.NewTicker(retryMonitorDelay).C {
		for ifaceName, bpfList := range bpfProgs {
			if bpfList == nil { // no bpf programs are running
				continue
			}
			for e := bpfList.Front(); e != nil; e=e.Next() {
				bpf := e.Value.(*BPF)
				if c.Chain && bpf.Program.SeqID == 0 { // do not monitor root program
					continue
				}
				isRunning, _ := bpf.isRunning()
				if isRunning == true {
					stats.Set(1.0, stats.NFRunning, bpf.Program.Name, direction)
					continue
				}
				if bpf.Program.AdminStatus == models.Disabled || !bpf.Monitor {
					continue
				}
				if bpf.RestartCount < c.MaxRetryCount {
					bpf.RestartCount++
					logs.Warningf("pMonitor BPF Program is not running - restart attempt %d -  program name - %s on iface %s",
						bpf.RestartCount, bpf.Program.Name, ifaceName)
					logs.IfErrorLogf(bpf.Start(ifaceName, direction, c.Chain), "pMonitor BPF Program start failed - %s",  bpf.Program.Name)
				} else {
					stats.Set(0.0, stats.NFRunning, bpf.Program.Name, direction)
				}
			}
		}
	}
}
