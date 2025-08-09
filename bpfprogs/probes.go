// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !WINDOWS
// +build !WINDOWS

package bpfprogs

import (
	"fmt"
	"strings"
	"time"

	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/stats"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/rs/zerolog/log"
)

func (b *BPF) LoadBPFProgramProbeType(prog *ebpf.Program, sectionName string) error {
	var progType, hookName, subType string

	switch prog.Type() {
	case ebpf.TracePoint:
		progType, hookName, subType = GetProgramSectionDetails(sectionName)
		tp, err := link.Tracepoint(hookName, subType, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to link tracepoint sec name %s error %v", sectionName, err)
		}
		b.ProbeLinks = append(b.ProbeLinks, &tp)
	case ebpf.Kprobe:
		progType, hookName, _ = GetProgramSectionDetails(sectionName)
		kp, err := b.AttachProbePerfEvent(hookName, progType, prog)
		if err != nil {
			return fmt.Errorf("failed to attach perf event error %v", err)
		}
		b.ProbeLinks = append(b.ProbeLinks, &kp)
	default:
		return fmt.Errorf("un-supported probe type %s ", prog.Type())
	}
	ebpfProgName := b.Program.Name + "_" + progType + "_" + hookName
	stats.Add(1, stats.BPFStartCount, ebpfProgName, "", "")
	stats.Set(float64(time.Now().Unix()), stats.BPFStartTime, ebpfProgName, "", "")
	return nil
}

// LoadBPFProgramProbeTypes - Load the BPF programs of probe types - TracePoint
func (b *BPF) LoadBPFProgramProbeTypes(objSpec *ebpf.CollectionSpec) error {
	for i, prog := range b.ProgMapCollection.Programs {
		if prog.Type() == ebpf.XDP || prog.Type() == ebpf.SchedACT || prog.Type() == ebpf.SchedCLS {
			// skipping XDP/TC programs
			continue
		}
		if err := b.LoadBPFProgramProbeType(prog, objSpec.Programs[i].SectionName); err != nil {
			return err
		}
		for _, tmpMap := range b.Program.MonitorMaps {
			tmpMetricsMap := b.ProgMapCollection.Maps[tmpMap.Name]
			if tmpMetricsMap == nil {
				log.Error().Msgf("%s map is not loaded", tmpMap.Name)
				continue
			}
		}
	}
	return nil
}

// GetProgramSectionDetails returns group and name details
// Section name format prog-type/hook/subtype
// ret : prog-type, hook, subtype
// e.g.: tracepoint/sock/inet_sock_set_state
// e.g.: kprobe/sys_execve
// e.g.: uprobe/<path>:<provider>:<name>
func GetProgramSectionDetails(sectionName string) (string, string, string) {
	sections := strings.Split(sectionName, "/")

	switch strings.ToLower(sections[0]) {
	case models.TracePoint:
		return sections[0], sections[1], sections[2]
	case models.KProbe, models.KRetProbe:
		return sections[0], sections[1], ""
	case models.UProbe, models.URetProbe:
		var funcName string
		if len(sections) > 2 {
			funcName = strings.Join(sections[1:], "/")
		}
		return sections[0], funcName, ""
	default:
		return "", "", ""
	}
}

func (b *BPF) AttachProbePerfEvent(hookName, progType string, prog *ebpf.Program) (link.Link, error) {
	var kp link.Link
	var err error
	switch strings.ToLower(progType) {
	case models.KProbe:
		kp, err = link.Kprobe(hookName, prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to link kprobe hook name %s error %v", hookName, err)
		}
	case models.KRetProbe:
		kp, err = link.Kretprobe(hookName, prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to link kretprobe hook name %s error %v", hookName, err)
		}
	case models.UProbe:
		kp, err = b.AttachUProbePerfEvent(hookName, prog)
		if err != nil {
			return nil, fmt.Errorf("failed to attach uprobe program %v", err)
		}
	case models.URetProbe:
		kp, err = b.AttachURetProbePerfEvent(hookName, prog)
		if err != nil {
			return nil, fmt.Errorf("failed to attach uretprobe program %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported perf event progType: %s", progType)
	}
	return kp, nil
}

func (b *BPF) AttachUProbePerfEvent(hookName string, prog *ebpf.Program) (link.Link, error) {
	var kp link.Link
	funcNames := strings.Split(hookName, ":")
	ex, err := link.OpenExecutable(funcNames[0])
	if err != nil {
		return nil, fmt.Errorf("uprobe failed to openExecutable binary file %s error %v", hookName, err)
	}

	kp, err = ex.Uprobe(getSymbolName(funcNames), prog, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to link uprobe symbol %s - %v", getSymbolName(funcNames), err)
	}

	return kp, nil
}

func (b *BPF) AttachURetProbePerfEvent(hookName string, prog *ebpf.Program) (link.Link, error) {
	var kp link.Link
	funcNames := strings.Split(hookName, ":")
	ex, err := link.OpenExecutable(funcNames[0])
	if err != nil {
		return nil, fmt.Errorf("uretprobe failed to openExecutable binary file %s error %v", hookName, err)
	}

	kp, err = ex.Uretprobe(getSymbolName(funcNames), prog, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to link uretprobe symbol %s - %v", getSymbolName(funcNames), err)
	}

	return kp, nil
}

func getSymbolName(funcNames []string) string {
	var symbol string
	if len(funcNames) == 1 {
		symbol = funcNames[0]
	} else {
		symbol = funcNames[len(funcNames)-1]
	}
	return symbol
}
