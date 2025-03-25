// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package restart provides primitives for gracefully restarting l3afd
package restart

import (
	"bytes"
	"container/list"
	"container/ring"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// convertBPFMap will  populate bpf maps from deserialized map names
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

// getCollection will populate ebpf Collection from deserialized meta collection object
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

// getMetricsMaps will populate MetricsBPFMap from deserialized meta metric object
func getMetricsMaps(input map[string]models.MetaMetricsBPFMap, b *bpfprogs.BPF, conf *config.Config, output *map[string]*bpfprogs.MetricsBPFMap, iface string) error {
	if input == nil {
		return nil
	}
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

// deserializeProgram will deserialize individual program from given *models.L3AFMetaData
func deserializeProgram(ctx context.Context, r *models.L3AFMetaData, hostconfig *config.Config, iface, direction string) (*bpfprogs.BPF, error) {
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
	if r.Link {
		var linkPinPath string
		if g.Program.ProgType == models.XDPType {
			linkPinPath = fmt.Sprintf("%s/links/%s/%s_%s", hostconfig.BpfMapDefaultPath, iface, g.Program.Name, g.Program.ProgType)
		} else {
			linkPinPath = fmt.Sprintf("%s/links/%s/%s_%s_%s", hostconfig.BpfMapDefaultPath, iface, g.Program.Name, g.Program.ProgType, direction)
		}
		var err error
		g.Link, err = link.LoadPinnedLink(linkPinPath, nil)
		if err != nil {
			return nil, err
		}
	}
	if err := getCollection(r.ProgMapCollection, &g.ProgMapCollection, g, iface); err != nil {
		return nil, err
	}
	return g, nil
}

// GetValueofLabel will query label value from given label array
func getValueofLabel(l string, t []models.Label) string {
	for _, f := range t {
		if f.Name == l {
			return f.Value
		}
	}
	return ""
}

// GetGaugeVecByMetricName will provide CounterVec metrics pointer from metric name
func getCountVecByMetricName(name string) *prometheus.CounterVec {
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

// GetGaugeVecByMetricName will provide GaugeVec metrics pointer from metric name
func getGaugeVecByMetricName(name string) *prometheus.GaugeVec {
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

// Convert will produce *bpfprogs.NFConfigs from deserilzed l3afd state
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
	if t.IngressXDPBpfs != nil {
		for k, v := range t.IngressXDPBpfs {
			l := list.New()
			for _, r := range v {
				f, err := deserializeProgram(ctx, r, hostconfig, k, models.XDPIngressType)
				if err != nil {
					log.Err(err).Msg("Deserialization failed for xdp ingress programs")
					return nil, err
				}
				l.PushBack(f)
			}
			D.IngressXDPBpfs[k] = l
		}
	}
	if t.IngressTCBpfs != nil {
		for k, v := range t.IngressTCBpfs {
			l := list.New()
			for _, r := range v {
				f, err := deserializeProgram(ctx, r, hostconfig, k, models.IngressType)
				if err != nil {
					log.Err(err).Msg("Deserialization failed for tc ingress programs")
					return nil, err
				}
				l.PushBack(f)
			}
			D.IngressTCBpfs[k] = l
		}
	}
	if t.EgressTCBpfs != nil {
		for k, v := range t.EgressTCBpfs {
			l := list.New()
			for _, r := range v {
				f, err := deserializeProgram(ctx, r, hostconfig, k, models.EgressType)
				if err != nil {
					log.Err(err).Msg("Deserialization failed for tc egress programs")
					return nil, err
				}
				l.PushBack(f)
			}
			D.EgressTCBpfs[k] = l
		}
	}
	return D, nil
}

// SetMetrics will populate all stats from models.L3AFALLHOSTDATA
func SetMetrics(t models.L3AFALLHOSTDATA) {
	for _, f := range t.AllStats {
		if f.Type == 0 {
			stats.Add(f.Value, getCountVecByMetricName(f.MetricName), getValueofLabel("ebpf_program", f.Labels),
				getValueofLabel("direction", f.Labels), getValueofLabel("interface_name", f.Labels))
		} else {
			if len(getValueofLabel("version", f.Labels)) > 0 {
				stats.SetWithVersion(f.Value, getGaugeVecByMetricName(f.MetricName), getValueofLabel("ebpf_program", f.Labels),
					getValueofLabel("version", f.Labels), getValueofLabel("direction", f.Labels), getValueofLabel("interface_name", f.Labels))
			} else if len(getValueofLabel("map_name", f.Labels)) > 0 {
				stats.SetValue(f.Value, getGaugeVecByMetricName(f.MetricName), getValueofLabel("ebpf_program", f.Labels),
					getValueofLabel("map_name", f.Labels), getValueofLabel("interface_name", f.Labels))
			} else {
				stats.Set(f.Value, getGaugeVecByMetricName(f.MetricName), getValueofLabel("ebpf_program", f.Labels),
					getValueofLabel("direction", f.Labels), getValueofLabel("interface_name", f.Labels))
			}
		}
	}
}

// GetNetListener will get tcp listner from provided file descriptor
func GetNetListener(fd int, fname string) (*net.TCPListener, error) {
	file := os.NewFile(uintptr(fd), "DupFd"+fname)
	l, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	lf, e := l.(*net.TCPListener)
	if !e {
		return nil, fmt.Errorf("unable to convert to tcp listener")
	}
	file.Close()
	return lf, nil
}

// AddSymlink to add symlink
func AddSymlink(sPath, symlink string) error {
	err := os.Symlink(sPath, symlink)
	return err
}

// RemoveSymlink to remove symlink
func RemoveSymlink(symlink string) error {
	err := os.Remove(symlink)
	return err
}

// ReadSymlink to read symlink
func ReadSymlink(symlink string) (string, error) {
	originalPath, err := os.Readlink(symlink)
	if err != nil {
		return "", err
	}
	return originalPath, nil
}

// GetNewVersion will download new version make it ready to execute
func GetNewVersion(artifactName, oldVersion, newVersion string, conf *config.Config) error {
	if oldVersion == newVersion {
		return nil
	}

	newVersionPath := filepath.Clean(filepath.Join(conf.BasePath, newVersion))
	err := os.RemoveAll(newVersionPath)
	if err != nil {
		return fmt.Errorf("error while deleting directory: %w", err)
	}
	err = os.MkdirAll(newVersionPath, 0750)
	if err != nil {
		return fmt.Errorf("error while creating directory: %w", err)
	}

	// now I need to download artifacts
	buf := &bytes.Buffer{}
	urlpath, err := url.JoinPath(conf.RestartArtifactURL, newVersion, artifactName)
	if err != nil {
		return fmt.Errorf("error while joining artifact path %w", err)
	}
	err = bpfprogs.DownloadArtifact(urlpath, conf.HttpClientTimeout, buf)
	if err != nil {
		return fmt.Errorf("unable to download artifacts %w", err)
	}
	err = bpfprogs.ExtractArtifact(artifactName, buf, newVersionPath)
	if err != nil {
		return fmt.Errorf("unable to extract artifacts %w", err)
	}

	// removing symlinks for old version
	err = RemoveSymlink(filepath.Join(conf.BasePath, "latest/l3afd"))
	if err != nil {
		return fmt.Errorf("unable to remove symlink %w", err)
	}
	err = RemoveSymlink(filepath.Join(conf.BasePath, "latest/l3afd.cfg"))
	if err != nil {
		return fmt.Errorf("unable to remove symlink %w", err)
	}

	// adding new version symlinks
	err = AddSymlink(filepath.Join(newVersionPath, "l3afd", "l3afd"), filepath.Join(conf.BasePath, "latest/l3afd"))
	if err != nil {
		return fmt.Errorf("unable to add symlink %w", err)
	}

	err = AddSymlink(filepath.Join(newVersionPath, "l3afd", "l3afd.cfg"), filepath.Join(conf.BasePath, "latest/l3afd.cfg"))
	if err != nil {
		return fmt.Errorf("unable to add symlink %w", err)
	}
	return nil
}

// RollBackSymlink will rollback binary & cfgfile symlinks to old version
func RollBackSymlink(oldCfgPath, oldBinPath string, oldVersion, newVersion string, conf *config.Config) error {
	if oldVersion == newVersion {
		return nil
	}

	err := RemoveSymlink(filepath.Join(conf.BasePath, "latest/l3afd"))
	if err != nil {
		return fmt.Errorf("unable to remove symlink %w", err)
	}
	err = RemoveSymlink(filepath.Join(conf.BasePath, "latest/l3afd.cfg"))
	if err != nil {
		return fmt.Errorf("unable to remove symlink %w", err)
	}

	// add new symlink
	err = AddSymlink(oldBinPath, filepath.Join(conf.BasePath, "latest/l3afd"))
	if err != nil {
		return fmt.Errorf("unable to add symlink %w", err)
	}

	err = AddSymlink(oldCfgPath, filepath.Join(conf.BasePath, "latest/l3afd.cfg"))
	if err != nil {
		return fmt.Errorf("unable to add symlink %w", err)
	}

	newVersionPath := filepath.Join(conf.BasePath, newVersion)
	if strings.Contains(newVersionPath, "..") {
		return fmt.Errorf("malicious path")
	}
	err = os.RemoveAll(newVersionPath)
	if err != nil {
		return fmt.Errorf("error while deleting directory: %w", err)
	}
	return nil
}
