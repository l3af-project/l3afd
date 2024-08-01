package restart

import (
	"container/list"
	"container/ring"
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/stats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

func convertBPFMap(in []string, g *bpfprogs.BPF, output *map[string]bpfprogs.BPFMap, iface string) error {
	for _, v := range in {
		var pinnedPath string
		if g.Program.ProgType == models.XDPType {
			pinnedPath = filepath.Join(g.HostConfig.BpfMapDefaultPath, iface, v)
		} else {
			pinnedPath = filepath.Join(g.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, iface, v)
		}
		m, err := ebpf.LoadPinnedMap(pinnedPath, nil)
		if err != nil {
			return err
		}
		info, err := m.Info()
		if err != nil {
			return err
		}
		id, _ := info.ID()
		(*output)[v] = bpfprogs.BPFMap{
			Name:    v,
			MapID:   id,
			Type:    info.Type,
			BPFProg: g,
		}
		m.Close()
	}
	return nil
}

func getCollection(input models.MetaColl, output **ebpf.Collection, b *bpfprogs.BPF, iface string) error {
	for _, v := range input.Programs {
		progPinPath := fmt.Sprintf("%s/progs/%s/%s_%s", b.HostConfig.BpfMapDefaultPath, iface, b.Program.EntryFunctionName, b.Program.ProgType)
		prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
		if err != nil {
			return err
		}
		(*output).Programs[v] = prog
	}
	for _, v := range input.Maps {
		var mapPinPath string
		if b.Program.ProgType == models.TCType {
			mapPinPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, iface, v)
		} else if b.Program.ProgType == models.XDPType {
			mapPinPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, iface, v)
		}
		m, err := ebpf.LoadPinnedMap(mapPinPath, nil)
		if err != nil {
			return err
		}
		(*output).Maps[v] = m
	}
	return nil
}

func getMetricsMaps(input map[string]models.MetaMetricsBPFMap, b *bpfprogs.BPF, conf *config.Config, output *map[string]*bpfprogs.MetricsBPFMap, iface string) error {
	for k, v := range input {
		fg := &bpfprogs.MetricsBPFMap{}
		var pinnedPath string
		if b.Program.ProgType == models.XDPType {
			pinnedPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, iface, v.MapName)
		} else {
			pinnedPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, iface, v.MapName)
		}
		m, err := ebpf.LoadPinnedMap(pinnedPath, nil)
		if err != nil {
			return err
		}
		info, err := m.Info()
		if err != nil {
			return err
		}
		id, _ := info.ID()
		fg.BPFMap = bpfprogs.BPFMap{
			Name:    v.MapName,
			MapID:   id,
			Type:    info.Type,
			BPFProg: b,
		}
		fg.Values = ring.New(conf.NMetricSamples)
		for _, a := range v.Values {
			fg.Values.Value = a
			fg.Values = fg.Values.Next()
		}
		fg.Aggregator = v.Aggregator
		fg.Key = v.Key
		fg.LastValue = v.LastValue
		(*output)[k] = fg
		m.Close()
	}
	return nil
}

func DeserilazeProgram(ctx context.Context, r *models.L3AFMetaData, hostconfig *config.Config, iface string) (*bpfprogs.BPF, error) {
	g := &bpfprogs.BPF{}
	g.Program = r.Program
	g.FilePath = r.FilePath
	g.RestartCount = r.RestartCount
	g.MapNamePath = r.MapNamePath
	g.PrevMapNamePath = r.PrevMapNamePath
	g.PrevProgMapID = ebpf.MapID(r.PrevProgMapID)
	g.ProgMapID = ebpf.MapID(r.ProgMapID)
	g.ProgID = ebpf.ProgramID(r.ProgID)
	g.Ctx = ctx
	g.HostConfig = hostconfig
	g.Done = nil
	g.BpfMaps = make(map[string]bpfprogs.BPFMap)
	if err := convertBPFMap(r.BpfMaps, g, &g.BpfMaps, iface); err != nil {
		return nil, err
	}
	g.MetricsBpfMaps = make(map[string]*bpfprogs.MetricsBPFMap)
	if err := getMetricsMaps(r.MetricsBpfMaps, g, hostconfig, &g.MetricsBpfMaps, iface); err != nil {
		return nil, fmt.Errorf("metrics maps conversion failed")
	}
	g.ProgMapCollection = &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
		Maps:     make(map[string]*ebpf.Map),
	}
	if r.XDPLink {
		linkPinPath := fmt.Sprintf("%s/links/%s/%s_%s", hostconfig.BpfMapDefaultPath, iface, g.Program.Name, g.Program.ProgType)
		var err error
		g.XDPLink, err = link.LoadPinnedLink(linkPinPath, nil)
		if err != nil {
			return nil, err
		}
	}
	if err := getCollection(r.ProgMapCollection, &g.ProgMapCollection, g, iface); err != nil {
		return nil, err
	}
	return g, nil
}

func ConvertIfaceMaps(ctx context.Context, input map[string][]*models.L3AFMetaData, output *map[string]*list.List, hostconfig *config.Config) error {
	return nil
}
func GetValueofLabel(l string, t []models.Label) string {
	for _, f := range t {
		if f.Name == l {
			return f.Value
		}
	}
	return ""
}

func GetCountVecByMetricName(name string) *prometheus.CounterVec {
	switch name {
	case "l3afd_BPFUpdateCount":
		return stats.BPFUpdateCount
	case "l3afd_BPFStartCount":
		return stats.BPFStartCount
	case "l3afd_BPFStopCount":
		return stats.BPFStopCount
	case "l3afd_BPFUpdateFailedCount":
		return stats.BPFUpdateFailedCount
	default:
		return nil
	}
}
func GetGaugeVecByMetricName(name string) *prometheus.GaugeVec {
	switch name {
	case "l3afd_BPFRunning":
		return stats.BPFRunning
	case "l3afd_BPFStartTime":
		return stats.BPFStartTime
	case "l3afd_BPFMonitorMap":
		return stats.BPFMonitorMap
	default:
		return nil
	}
}
func Convert(ctx context.Context, t models.L3AFALLHOSTDATA, hostconfig *config.Config) (*bpfprogs.NFConfigs, error) {
	D := &bpfprogs.NFConfigs{}
	D.Ctx = ctx
	D.HostName = t.HostName
	D.HostInterfaces = t.HostInterfaces
	D.Ifaces = t.Ifaces
	D.IngressXDPBpfs = make(map[string]*list.List)
	D.IngressTCBpfs = make(map[string]*list.List)
	D.EgressTCBpfs = make(map[string]*list.List)
	D.ProbesBpfs = *list.New()
	D.HostConfig = hostconfig
	D.Mu = new(sync.Mutex)
	for k, v := range t.IngressXDPBpfs {
		l := list.New()
		for _, r := range v {
			f, err := DeserilazeProgram(ctx, r, hostconfig, k)
			if err != nil {
				log.Err(err).Msg("Deserilization failed for xdpingress")
				return nil, err
			}
			l.PushBack(f)
		}
		D.IngressXDPBpfs[k] = l
	}

	for k, v := range t.IngressTCBpfs {
		l := list.New()
		for _, r := range v {
			f, err := DeserilazeProgram(ctx, r, hostconfig, k)
			if err != nil {
				log.Err(err).Msg("Deserilization failed for tcingress")
				return nil, err
			}
			l.PushBack(f)
		}
		D.IngressTCBpfs[k] = l
	}

	for k, v := range t.EgressTCBpfs {
		l := list.New()
		for _, r := range v {
			f, err := DeserilazeProgram(ctx, r, hostconfig, k)
			if err != nil {
				log.Err(err).Msg("Deserilization failed for tcegress")
				return nil, err
			}
			l.PushBack(f)
		}
		D.EgressTCBpfs[k] = l
	}
	return D, nil
}

// Setting up Metrics
func SetMetrics(t models.L3AFALLHOSTDATA) {
	for _, f := range t.AllStats {
		if f.Type == 0 {
			stats.Add(f.Value, GetCountVecByMetricName(f.MetricName), GetValueofLabel("ebpf_program", f.Labels),
				GetValueofLabel("direction", f.Labels), GetValueofLabel("interface_name", f.Labels))
		} else {
			if len(GetValueofLabel("version", f.Labels)) > 0 {
				stats.SetWithVersion(f.Value, GetGaugeVecByMetricName(f.MetricName), GetValueofLabel("ebpf_program", f.Labels),
					GetValueofLabel("version", f.Labels), GetValueofLabel("direction", f.Labels), GetValueofLabel("interface_name", f.Labels))
			} else if len(GetValueofLabel("map_name", f.Labels)) > 0 {
				stats.SetValue(f.Value, GetGaugeVecByMetricName(f.MetricName), GetValueofLabel("ebpf_program", f.Labels),
					GetValueofLabel("map_name", f.Labels), GetValueofLabel("interface_name", f.Labels))
			} else {
				stats.Set(f.Value, GetGaugeVecByMetricName(f.MetricName), GetValueofLabel("ebpf_program", f.Labels),
					GetValueofLabel("direction", f.Labels), GetValueofLabel("interface_name", f.Labels))
			}
		}
	}
}
