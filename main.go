// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"tbd/go-shared/pidfile"
	version "tbd/go-version"
	"tbd/l3afd/config"
	"tbd/l3afd/kf"
	"tbd/l3afd/stats"

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

func main() {
	setupLogging()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Info().Msgf("%s started.", daemonName)

	var confPath string
	flag.StringVar(&confPath, "config", "config/l3afd.cfg", "config path")

	flag.Parse()
	version.Init()
	conf, err := config.ReadConfig(confPath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Unable to parse config %q", confPath)
	}

	if err = pidfile.CheckPIDConflict(conf.PIDFilename); err != nil {
		log.Fatal().Err(err).Msgf("The PID file: %s, is in an unacceptable state", conf.PIDFilename)
	}
	if err = pidfile.CreatePID(conf.PIDFilename); err != nil {
		log.Fatal().Err(err).Msgf("The PID file: %s, could not be created", conf.PIDFilename)
	}

	if err = checkKernelVersion(conf); err != nil {
		log.Fatal().Err(err).Msg("The unsupported kernel version please upgrade")
	}

	if err = registerL3afD(conf); err != nil {
		log.Error().Err(err).Msg("L3afd registration failed")
	}

	kfConfigs, err := SetupNFConfigs(ctx, conf)
	if err != nil {
		log.Fatal().Err(err).Msg("L3afd failed to start")
	}

	if conf.EBPFChainDebugEnabled {
		kf.SetupKFDebug(conf.EBPFChainDebugAddr, kfConfigs)
	}
	select {}
}

func SetupNFConfigs(ctx context.Context, conf *config.Config) (*kf.NFConfigs, error) {
	// Get Hostname
	machineHostname, err := os.Hostname()
	if err != nil {
		log.Error().Err(err).Msg("Could not get hostname from OS")
	}

	// setup Metrics endpoint
	stats.SetupMetrics(machineHostname, daemonName, conf.MetricsAddr)

	pMon := kf.NewpCheck(conf.MaxNFReStartCount, conf.BpfChainingEnabled, conf.KFPollInterval)
	kfM := kf.NewpKFMetrics(conf.BpfChainingEnabled, conf.NMetricSamples)

	nfConfigs, err := kf.NewNFConfigs(ctx, machineHostname, conf, pMon, kfM)
	if err != nil {
		return nil, fmt.Errorf("error in NewNFConfigs setup: %v", err)
	}

	if err := kf.StartConfigWatcher(ctx, machineHostname, daemonName, conf, nfConfigs); err != nil {
		return nil, fmt.Errorf("error in version announcer: %v", err)
	}

	return nfConfigs, nil
}

func checkKernelVersion(conf *config.Config) error {
	const minVerLen = 2

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return fmt.Errorf("Failed to find kernel version: %v", err)
	}

	//validate version
	ver := strings.Split(kernelVersion, ".")
	if len(ver) < minVerLen {
		return fmt.Errorf("Expected minimum kernel version length %d and got %d, ver %+q", minVerLen, len(ver), ver)
	}
	major_ver, err := strconv.Atoi(ver[0])
	if err != nil {
		return fmt.Errorf("Failed to find kernel major version: %v", err)
	}
	minor_ver, err := strconv.Atoi(ver[1])
	if err != nil {
		return fmt.Errorf("Failed to find kernel minor version: %v", err)
	}

	if major_ver > conf.MinKernelMajorVer {
		return nil
	}
	if major_ver == conf.MinKernelMajorVer && minor_ver >= conf.MinKernelMinorVer {
		return nil
	}

	return fmt.Errorf("Expected Kernel version >=  %d.%d", conf.MinKernelMajorVer, conf.MinKernelMinorVer)
}

func getKernelVersion() (string, error) {
	osVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("Failed to read procfs: %v", err)
	}
	var u1, u2, kernelVersion string
	_, err = fmt.Sscanf(string(osVersion), "%s %s %s", &u1, &u2, &kernelVersion)
	if err != nil {
		return "", fmt.Errorf("Failed to scan procfs version: %v", err)
	}

	return kernelVersion, nil
}
