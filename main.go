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
	"net"
	"os"
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

func covertBPFMap(m map[string]models.MetaBpfMap, g *bpfprogs.BPF, output *map[string]bpfprogs.BPFMap) {
	for k, v := range m {
		p := bpfprogs.BPFMap{}
		p.MapID = ebpf.MapID(v.MapID)
		p.Type = ebpf.MapType(v.Type)
		p.Name = v.Name
		p.BPFProg = g
		(*output)[k] = p
	}
}

func getCollection(input models.MetaColl, output **ebpf.Collection) error {
	for k, v := range input.Programs {
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(v.ProgID))
		if err != nil {
			return fmt.Errorf("getting map collection failed %w", err)
		}
		(*output).Programs[k] = prog
	}
	for k, v := range input.Maps {
		m, err := ebpf.NewMapFromID(ebpf.MapID(v.MapID))
		if err != nil {
			return fmt.Errorf("getting map collection failed %w", err)
		}
		(*output).Maps[k] = m
	}
	return nil
}

func getMetricsMaps(input map[string]models.MetaMetricsBPFMap, b *bpfprogs.BPF, conf *config.Config, output *map[string]*bpfprogs.MetricsBPFMap) {
	for k, v := range input {
		fg := &bpfprogs.MetricsBPFMap{}
		fg.Key = v.Key
		fg.LastValue = float64(v.LastValue)
		fg.BPFMap.MapID = ebpf.MapID(v.MapID)
		fg.BPFMap.Name = v.Name
		fg.Aggregator = v.Aggregator
		fg.BPFProg = b
		fg.Values = ring.New(conf.NMetricSamples)
		for _, a := range v.Values {
			fg.Values.Value = a
			fg.Values = fg.Values.Next()
		}
		(*output)[k] = fg
	}
}

func ConvertIfaceMaps(ctx context.Context, input map[string][]*models.L3AFMetaData, output *map[string]*list.List, hostconfig *config.Config) error {
	var err error
	for k, v := range input {
		l := list.New()
		for _, r := range v {
			g := &bpfprogs.BPF{}
			g.Program = r.Program
			g.FilePath = r.FilePath
			g.RestartCount = r.RestartCount
			g.MapNamePath = r.MapNamePath
			g.PrevMapNamePath = r.PrevMapNamePath
			g.PrevProgMapID = ebpf.MapID(r.PrevProgMapID)
			g.ProgID = ebpf.ProgramID(r.ProgID)
			g.Ctx = ctx
			g.HostConfig = hostconfig
			g.Done = nil
			g.BpfMaps = make(map[string]bpfprogs.BPFMap)
			covertBPFMap(r.BpfMaps, g, &g.BpfMaps)
			g.ProgMapCollection = &ebpf.Collection{
				Programs: make(map[string]*ebpf.Program),
				Maps:     make(map[string]*ebpf.Map),
			}
			getCollection(r.ProgMapCollection, &g.ProgMapCollection)
			g.MetricsBpfMaps = make(map[string]*bpfprogs.MetricsBPFMap)
			getMetricsMaps(r.MetricsBpfMaps, g, hostconfig, &g.MetricsBpfMaps)
			if r.XDPLink >= 3 {
				g.XDPLink, err = link.NewLinkFromFD(r.XDPLink)
				if err != nil {
					return fmt.Errorf("Coversion error %w", err)
				}
				models.CurrentFdIdx++
			}
			for _, a := range r.ProbeLinks {
				ln, kerr := link.NewLinkFromFD(a)
				if kerr != nil {
					return fmt.Errorf("getting fd from problink failed %w", kerr)
				}
				g.ProbeLinks = append(g.ProbeLinks, &ln)
				models.CurrentFdIdx++
			}
			l.PushBack(g)
		}
		(*output)[k] = l
	}
	return nil
}
func Convert(ctx context.Context, t models.L3AFALLHOSTDATA, hostconfig *config.Config) (*bpfprogs.NFConfigs, error) {
	D := &bpfprogs.NFConfigs{}
	D.Ctx = ctx
	D.HostName = t.HostName
	D.HostInterfaces = t.HostInterfaces
	D.Ifaces = t.Ifaces
	D.BpfMetricsMon = bpfprogs.NewpBpfMetrics(t.BpfMetricsMon.Chain, t.BpfMetricsMon.Intervals)
	D.ProcessMon = bpfprogs.NewPCheck(t.ProcessMon.MaxRetryCount, t.BpfMetricsMon.Chain, time.Duration(t.ProcessMon.RetryMonitorDelay))
	D.IngressXDPBpfs = make(map[string]*list.List)
	D.IngressTCBpfs = make(map[string]*list.List)
	D.EgressTCBpfs = make(map[string]*list.List)
	D.ProbesBpfs = *list.New()
	D.HostConfig = hostconfig
	D.Mu = new(sync.Mutex)
	if err := ConvertIfaceMaps(ctx, t.IngressXDPBpfs, &D.IngressXDPBpfs, hostconfig); err != nil {
		return nil, err
	}
	return D, nil
}

func getnetlistener(fd int) (*net.TCPListener, error) {
	file := os.NewFile(uintptr(fd), "DupFD"+strconv.Itoa(models.CurrentFdIdx))
	l, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	lf, e := l.(*net.TCPListener)
	if !e {
		return nil, fmt.Errorf("not able to covert to tcp listner")
	}
	return lf, nil
}

func main() {
	setupLogging()
	models.CurrentFdIdx = 3
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

	if conf.HotReloadEnabled {
		bodyBuffer, err := os.ReadFile("/var/l3afd/l3af_meta.json")
		if err != nil {
			log.Info().Msgf("not able to read meta data file")
		}
		var t models.L3AFALLHOSTDATA
		if err := json.Unmarshal(bodyBuffer, &t); err != nil {
			mesg := fmt.Sprintf("failed to unmarshal payload: %v", err)
			log.Error().Msg(mesg)
			return
		}
		nfConfigs, err := Convert(ctx, t, conf)
		if err != nil {
			log.Fatal().Msgf("coversion of state failed %w", err)
		}
		l, err := getnetlistener(models.CurrentFdIdx)
		if err != nil {
			log.Fatal().Msgf("getting listner failed %w", err)
		}
		models.AllNetListeners = make(map[string]*net.TCPListener)
		models.AllNetListeners["stat_http"] = l
		models.CurrentFdIdx += 1

		l, err = getnetlistener(models.CurrentFdIdx)
		if err != nil {
			log.Fatal().Msgf("getting listner failed %w", err)
		}
		models.AllNetListeners["main_http"] = l
		models.CurrentFdIdx += 1

		if conf.EBPFChainDebugEnabled {
			l, err = getnetlistener(models.CurrentFdIdx)
			if err != nil {
				log.Fatal().Msgf("getting listner failed %w", err)
			}
			models.AllNetListeners["debug_http"] = l
			models.CurrentFdIdx += 1
		}
		models.CurrentFdIdx = 3
		// Get Hostname
		machineHostname, err := os.Hostname()
		if err != nil {
			log.Error().Err(err).Msg("Could not get hostname from OS")
		}
		// setup Metrics endpoint
		stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)

		if err := apis.StartConfigWatcher(ctx, machineHostname, daemonName, conf, nfConfigs); err != nil {
			log.Fatal().Msgf("starting config watched failed %w", err)
		}
		if err := handlers.InitConfigs(nfConfigs); err != nil {
			log.Fatal().Err(err).Msg("L3afd failed to initialise configs")
		}
		select {}
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
	select {}
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
