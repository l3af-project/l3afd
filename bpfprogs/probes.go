// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

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
		var kp link.Link
		var err error
		if strings.ToLower(progType) == models.KProbe {
			kp, err = link.Kprobe(hookName, prog, nil)
			if err != nil {
				return fmt.Errorf("failed to link kprobe sec name %s error %v", sectionName, err)
			}
		} else if strings.ToLower(progType) == models.KRetProbe {
			kp, err = link.Kretprobe(hookName, prog, nil)
			if err != nil {
				return fmt.Errorf("failed to link kprobe sec name %s error %v", sectionName, err)
			}
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
func GetProgramSectionDetails(sectionName string) (string, string, string) {
	sections := strings.Split(sectionName, "/")

	switch strings.ToLower(sections[0]) {
	case models.TracePoint:
		return sections[0], sections[1], sections[2]
	case models.KProbe, models.KRetProbe:
		return sections[0], sections[1], ""
	default:
		return "", "", ""
	}
}
