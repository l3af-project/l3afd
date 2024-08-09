// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/gob"
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

	"github.com/l3af-project/l3afd/v2/apis"
	"github.com/l3af-project/l3afd/v2/apis/handlers"
	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/pidfile"
	"github.com/l3af-project/l3afd/v2/restart"
	"github.com/l3af-project/l3afd/v2/stats"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const daemonName = "l3afd"

var stateSockPath string

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

func main() {
	models.CloseForRestart = make(chan struct{})
	models.IsReadOnly = false
	models.CurrentWriteReq = 0
	models.StateLock = sync.Mutex{}
	models.AllNetListeners = make(map[string]*net.TCPListener)
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
		if err = setupForRestart(ctx, conf); err != nil {
			log.Warn().Msg("Doing Normal Startup")
		} else {
			log.Fatal().Err(err).Msgf("The PID file: %s, is in an unacceptable state", conf.PIDFilename)
		}
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

func HandleErr(e error, msg string) {
	if e == nil {
		return
	}
	log.Fatal().Err(e).Msgf(msg)
	sendState("Failed")
	os.Exit(0)
}
func setupForRestart(ctx context.Context, conf *config.Config) error {
	if _, err := os.Stat(conf.HostSock); os.IsNotExist(err) {
		return err
	}
	stateSockPath = conf.StateSock
	models.IsReadOnly = true
	// Now you need to write client side code
	conn, err := net.Dial("unix", conf.HostSock)
	defer conn.Close()
	HandleErr(err, "not able to dial unix domain socket")
	decoder := gob.NewDecoder(conn)
	var t models.L3AFALLHOSTDATA
	err = decoder.Decode(&t)
	HandleErr(err, "not able to decode")
	machineHostname, err := os.Hostname()
	HandleErr(err, "not able to fetch the hostname")

	models.AllNetListeners = make(map[string]*net.TCPListener)
	l, err := restart.Getnetlistener(3, "stat_server")
	HandleErr(err, "getting stat_server listener failed")
	models.AllNetListeners["stat_http"] = l

	l, err = restart.Getnetlistener(4, "main_server")
	HandleErr(err, "getting main_server listener failed")
	models.AllNetListeners["main_http"] = l

	if conf.EBPFChainDebugEnabled {
		l, err = restart.Getnetlistener(5, "debug_server")
		HandleErr(err, "getting main_server listener failed")
		models.AllNetListeners["debug_http"] = l
	}
	// setup Metrics endpoint
	stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)
	restart.SetMetrics(t)
	pMon := bpfprogs.NewPCheck(conf.MaxEBPFReStartCount, conf.BpfChainingEnabled, conf.EBPFPollInterval)
	bpfM := bpfprogs.NewpBpfMetrics(conf.BpfChainingEnabled, conf.NMetricSamples)
	log.Info().Msgf("Restoring Previous State Graceful Restart")
	ebpfConfigs, err := restart.Convert(ctx, t, conf)
	ebpfConfigs.BpfMetricsMon = bpfM
	ebpfConfigs.ProcessMon = pMon
	HandleErr(err, "Failed to convert deserilaze the state")
	err = ebpfConfigs.StartAllUserProgramsAndProbes()
	HandleErr(err, "failed to start all the user programs and probes")
	err = apis.StartConfigWatcher(ctx, machineHostname, daemonName, conf, ebpfConfigs)
	HandleErr(err, "Starting config Watcher failed")
	err = handlers.InitConfigs(ebpfConfigs)
	HandleErr(err, "L3afd failed to initialise configs")
	if conf.EBPFChainDebugEnabled {
		bpfprogs.SetupBPFDebug(conf.EBPFChainDebugAddr, ebpfConfigs)
	}
	ebpfConfigs.ProcessMon.PCheckStart(ebpfConfigs.IngressXDPBpfs, ebpfConfigs.IngressTCBpfs, ebpfConfigs.EgressTCBpfs, &ebpfConfigs.ProbesBpfs)
	ebpfConfigs.BpfMetricsMon.BpfMetricsStart(ebpfConfigs.IngressXDPBpfs, ebpfConfigs.IngressTCBpfs, ebpfConfigs.EgressTCBpfs, &ebpfConfigs.ProbesBpfs)
	err = pidfile.CreatePID(conf.PIDFilename)
	HandleErr(err, fmt.Sprintf("The PID file: %s, could not be created", conf.PIDFilename))
	// we need to write code to send ready status
	sendState("Ready")
	models.IsReadOnly = false
	<-models.CloseForRestart
	os.Exit(0)
	return nil
}

func sendState(s string) {
	ln, err := net.Listen("unix", stateSockPath)
	if err != nil {
		log.Err(err)
		os.Exit(0)
		return
	}
	conn, err := ln.Accept()
	if err != nil {
		log.Err(err)
		ln.Close()
		os.Exit(0)
		return
	}
	encoder := gob.NewEncoder(conn)
	err = encoder.Encode(s)
	if err != nil {
		log.Err(err)
		conn.Close()
		ln.Close()
		os.Exit(0)
		return
	}
	conn.Close()
	ln.Close()
}
