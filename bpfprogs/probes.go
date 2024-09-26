// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"fmt"
	"strings"
	"time"

	"github.com/l3af-project/l3afd/v2/stats"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/rs/zerolog/log"
)

func (b *BPF) LoadBPFProgramProbeType(prog *ebpf.Program, sectionName string) error {
	var probeName, group string
	switch prog.Type() {
	case ebpf.TracePoint:
		group, probeName = GetProgramSectionDetails(sectionName)
		tp, err := link.Tracepoint(group, probeName, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to link tracepoint sec name %s error %v", sectionName, err)
		}
		b.ProbeLinks = append(b.ProbeLinks, &tp)
	case ebpf.Kprobe:
		_, probeName = GetProgramSectionDetails(sectionName)
		kp, err := link.Kprobe(probeName, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to link kprobe sec name %s error %v", sectionName, err)
		}
		b.ProbeLinks = append(b.ProbeLinks, &kp)
	default:
		return fmt.Errorf("un-supported probe type %s ", prog.Type())
	}
	ebpfProgName := b.Program.Name + "_" + probeName
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
// Section name format /prob type/group/name
// e.g.: tracepoint/sock/inet_sock_set_state
// e.g.: kprobe/sys_execve
func GetProgramSectionDetails(sectionName string) (string, string) {
	sections := strings.Split(sectionName, "/")
	length := len(sections)
	if length > 1 {
		return sections[length-2], sections[length-1]
	} else if length == 1 {
		return "", sections[0]
	}
	return "", ""
}
