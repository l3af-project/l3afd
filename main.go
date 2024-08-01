// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"container/list"
	"container/ring"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/l3af-project/l3afd/v2/apis"
	"github.com/l3af-project/l3afd/v2/apis/handlers"
	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/pidfile"
	"github.com/l3af-project/l3afd/v2/stats"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const daemonName = "l3afd"

func setupLogging() {
	const logLevelEnvName = "L3AF_LOG_LEVEL"

	// If this is removed, zerolog will do structured logging. For now,
	// we set zerolog to do human-readable logging just to keep the same
	// behavior as the closed-source logging package that we replaced with
	// zerolog.
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stderr, TimeFormat: time.RFC3339Nano})

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set the default
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	logLevelStr := os.Getenv(logLevelEnvName)
	if logLevelStr == "" {
		return
	}
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		log.Error().Err(err).Msg("Invalid L3AF_LOG_LEVEL")
		return
	}
	zerolog.SetGlobalLevel(logLevel)
	log.Debug().Msgf("Log level set to %q", logLevel)
}

func saveLogsToFile(conf *config.Config) {

	logFileWithRotation := &lumberjack.Logger{
		Filename:   conf.FileLogLocation,
		MaxSize:    conf.FileLogMaxSize,    // Max size in megabytes
		MaxBackups: conf.FileLogMaxBackups, // Max number of old log files to keep
		MaxAge:     conf.FileLogMaxAge,     // Max number of days to keep log files
	}
	multi := zerolog.MultiLevelWriter(os.Stdout, logFileWithRotation)
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: multi, TimeFormat: time.RFC3339Nano})
}

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

func main() {
	models.CloseForRestart = make(chan struct{})
	setupLogging()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Info().Msgf("%s started.", daemonName)

	var confPath string
	flag.StringVar(&confPath, "config", "config/l3afd.cfg", "config path")

	flag.Parse()
	initVersion()
	conf, err := config.ReadConfig(confPath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Unable to parse config %q", confPath)
	}
	if conf.FileLogLocation != "" {
		log.Info().Msgf("Saving logs to file: %s", conf.FileLogLocation)
		saveLogsToFile(conf)
	}

	if err = pidfile.CheckPIDConflict(conf.PIDFilename); err != nil {
		log.Fatal().Err(err).Msgf("The PID file: %s, is in an unacceptable state", conf.PIDFilename)
	}
	if err = pidfile.CreatePID(conf.PIDFilename); err != nil {
		log.Fatal().Err(err).Msgf("The PID file: %s, could not be created", conf.PIDFilename)
	}

	if runtime.GOOS == "linux" {
		if err = checkKernelVersion(conf); err != nil {
			log.Fatal().Err(err).Msg("The unsupported kernel version please upgrade")
		}
	}

	if err = registerL3afD(conf); err != nil {
		log.Error().Err(err).Msg("L3afd registration failed")
	}

	if err = setupForRestart(ctx, conf); err != nil {
		log.Warn().Msg("Doing Normal Startup")
	}

	ebpfConfigs, err := SetupNFConfigs(ctx, conf)
	if err != nil {
		log.Fatal().Err(err).Msg("L3afd failed to start")
	}

	t, err := ReadConfigsFromConfigStore(conf)
	if err != nil {
		log.Error().Err(err).Msg("L3afd failed to read configs from store")
	}

	if t != nil {
		if err := ebpfConfigs.DeployeBPFPrograms(t); err != nil {
			log.Error().Err(err).Msg("L3afd failed to deploy persistent configs from store")
		}
	}

	if err := handlers.InitConfigs(ebpfConfigs); err != nil {
		log.Fatal().Err(err).Msg("L3afd failed to initialise configs")
	}

	if conf.EBPFChainDebugEnabled {
		bpfprogs.SetupBPFDebug(conf.EBPFChainDebugAddr, ebpfConfigs)
	}
	<-models.CloseForRestart
	os.Exit(0)
}

func SetupNFConfigs(ctx context.Context, conf *config.Config) (*bpfprogs.NFConfigs, error) {
	// Get Hostname
	machineHostname, err := os.Hostname()
	if err != nil {
		log.Error().Err(err).Msg("Could not get hostname from OS")
	}
	// setup Metrics endpoint
	stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)

	pMon := bpfprogs.NewPCheck(conf.MaxEBPFReStartCount, conf.BpfChainingEnabled, conf.EBPFPollInterval)
	bpfM := bpfprogs.NewpBpfMetrics(conf.BpfChainingEnabled, conf.NMetricSamples)
	nfConfigs, err := bpfprogs.NewNFConfigs(ctx, machineHostname, conf, pMon, bpfM)
	if err != nil {
		return nil, fmt.Errorf("error in NewNFConfigs setup: %v", err)
	}

	if err := apis.StartConfigWatcher(ctx, machineHostname, daemonName, conf, nfConfigs); err != nil {
		return nil, fmt.Errorf("error in version announcer: %v", err)
	}

	return nfConfigs, nil
}

func checkKernelVersion(conf *config.Config) error {
	const minVerLen = 2

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to find kernel version: %v", err)
	}

	//validate version
	ver := strings.Split(kernelVersion, ".")
	if len(ver) < minVerLen {
		return fmt.Errorf("expected minimum kernel version length %d and got %d, ver %+q", minVerLen, len(ver), ver)
	}
	major_ver, err := strconv.Atoi(ver[0])
	if err != nil {
		return fmt.Errorf("failed to find kernel major version: %v", err)
	}
	minor_ver, err := strconv.Atoi(ver[1])
	if err != nil {
		return fmt.Errorf("failed to find kernel minor version: %v", err)
	}

	if major_ver > conf.MinKernelMajorVer {
		return nil
	}
	if major_ver == conf.MinKernelMajorVer && minor_ver >= conf.MinKernelMinorVer {
		return nil
	}

	return fmt.Errorf("expected Kernel version >=  %d.%d", conf.MinKernelMajorVer, conf.MinKernelMinorVer)
}

func getKernelVersion() (string, error) {
	osVersion, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("failed to read procfs: %v", err)
	}
	var u1, u2, kernelVersion string
	_, err = fmt.Sscanf(string(osVersion), "%s %s %s", &u1, &u2, &kernelVersion)
	if err != nil {
		return "", fmt.Errorf("failed to scan procfs version: %v", err)
	}

	return kernelVersion, nil
}

func ReadConfigsFromConfigStore(conf *config.Config) ([]models.L3afBPFPrograms, error) {

	// check for persistent file
	if _, err := os.Stat(conf.L3afConfigStoreFileName); errors.Is(err, os.ErrNotExist) {
		log.Warn().Msgf("no persistent config exists")
		return nil, nil
	}

	file, err := os.OpenFile(conf.L3afConfigStoreFileName, os.O_RDONLY, os.ModePerm)
	defer func() {
		_ = file.Close()
	}()

	if err != nil {
		return nil, fmt.Errorf("failed to open persistent file (%s): %v", conf.L3afConfigStoreFileName, err)
	}

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read persistent file (%s): %v", conf.L3afConfigStoreFileName, err)
	}

	var t []models.L3afBPFPrograms
	if err = json.Unmarshal(byteValue, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal persistent config json: %v", err)
	}
	return t, nil
}

func setupForRestart(ctx context.Context, conf *config.Config) error {
	bodyBuffer, err := os.ReadFile(conf.RestartDataFile)
	if err != nil {
		return fmt.Errorf("not able to read file")
	}
	var t models.L3AFALLHOSTDATA
	if err := json.Unmarshal(bodyBuffer, &t); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %v", err)
	}
	if t.InRestart {
		// Get Hostname
		machineHostname, err := os.Hostname()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not get hostname from OS")
		}
		// setup Metrics endpoint
		stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)
		SetMetrics(t)
		pMon := bpfprogs.NewPCheck(conf.MaxEBPFReStartCount, conf.BpfChainingEnabled, conf.EBPFPollInterval)
		bpfM := bpfprogs.NewpBpfMetrics(conf.BpfChainingEnabled, conf.NMetricSamples)
		log.Info().Msgf("Restoring Previous State (gracefull restart)")
		ebpfConfigs, err := Convert(ctx, t, conf)
		ebpfConfigs.BpfMetricsMon = bpfM
		ebpfConfigs.ProcessMon = pMon
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to convert state")
		}
		if err := ebpfConfigs.StartAllUserProgramsAndProbes(t); err != nil {
			log.Fatal().Err(err).Msg("failed to start all the user programs and probes")
		}
		if err := apis.StartConfigWatcher(ctx, machineHostname, daemonName, conf, ebpfConfigs); err != nil {
			log.Fatal().Err(err).Msgf("Starting config Watcher failed")
		}
		if err := handlers.InitConfigs(ebpfConfigs); err != nil {
			log.Fatal().Err(err).Msg("L3afd failed to initialise configs")
		}
		if conf.EBPFChainDebugEnabled {
			bpfprogs.SetupBPFDebug(conf.EBPFChainDebugAddr, ebpfConfigs)
		}
		ebpfConfigs.ProcessMon.PCheckStart(ebpfConfigs.IngressXDPBpfs, ebpfConfigs.IngressTCBpfs, ebpfConfigs.EgressTCBpfs, &ebpfConfigs.ProbesBpfs)
		ebpfConfigs.BpfMetricsMon.BpfMetricsStart(ebpfConfigs.IngressXDPBpfs, ebpfConfigs.IngressTCBpfs, ebpfConfigs.EgressTCBpfs, &ebpfConfigs.ProbesBpfs)
		t.InRestart = false
		file, err := json.MarshalIndent(t, "", " ")
		if err != nil {
			log.Error().Err(err).Msgf("failed to marshal configs to save")
		}
		if err = os.WriteFile(conf.RestartDataFile, file, 0644); err != nil {
			log.Error().Err(err).Msgf("failed write to file operation")
		}
		<-models.CloseForRestart
		os.Exit(0)
	}
	return nil
}
