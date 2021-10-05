// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package config provides primitives for l3afd configuration ( i.e. l3afd.cfg) file.
package config

import (
	"time"

	"github.com/robfig/config"
	"github.com/rs/zerolog/log"
)

type Config struct {
	PIDFilename       string
	DataCenter        string
	BPFDir            string
	BPFLogDir         string
	MinKernelMajorVer int
	MinKernelMinorVer int
	KFRepoURL         string
	HttpClientTimeout time.Duration
	MaxNFReStartCount int
	MaxNFsAttachCount int

	// Flag to enable chaining with root program
	BpfChainingEnabled bool

	// stats
	// Prometheus endpoint for pull/scrape the metrics.
	MetricsAddr    string
	KFPollInterval time.Duration
	NMetricSamples int

	ShutdownTimeout time.Duration

	// Admin API endpoint config for registering l3afd.
	AdmindHost       string
	AdmindUsername   string
	AdmindApiKey     string
	AdmindGroupID    int
	AdmindApiEnabled bool

	// XDP Root program details.
	XDPRootProgramName          string
	XDPRootProgramArtifact      string
	XDPRootProgramMapName       string
	XDPRootProgramCommand       string
	XDPRootProgramVersion       string
	XDPRootProgramIsUserProgram bool

	// TC Root program details.
	TCRootProgramName           string
	TCRootProgramArtifact       string
	TCRootProgramIngressMapName string
	TCRootProgramEgressMapName  string
	TCRootProgramCommand        string
	TCRootProgramVersion        string
	TCRootProgramIsUserProgram  bool

	// ebpf chain details
	EBPFChainDebugAddr    string
	EBPFChainDebugEnabled bool

	// l3af configs to listen addrs
	L3afConfigsgRPCAddr    string
	L3afConfigsRestAPIAddr string
}

//ReadConfig - Initializes configuration from file
func ReadConfig(configPath string) (*Config, error) {

	log.Info().Msgf("Reading configuration from: %s", configPath)
	confReader, configErr := config.ReadDefault(configPath)
	if configErr != nil {
		log.Fatal().Err(configErr).Msgf("Could not open config file %q", configPath)
	}

	return &Config{
		PIDFilename:                 LoadConfigString(confReader, "l3afd", "pid-file"),
		DataCenter:                  LoadConfigString(confReader, "l3afd", "datacenter"),
		BPFDir:                      LoadConfigString(confReader, "l3afd", "bpf-dir"),
		BPFLogDir:                   LoadConfigString(confReader, "l3afd", "bpf-log-dir"),
		MinKernelMajorVer:           LoadConfigInt(confReader, "l3afd", "kernel-major-version"),
		MinKernelMinorVer:           LoadConfigInt(confReader, "l3afd", "kernel-minor-version"),
		KFRepoURL:                   LoadConfigString(confReader, "kf-repo", "url"),
		HttpClientTimeout:           LoadConfigDuration(confReader, "l3afd", "http-client-timeout"),
		MaxNFReStartCount:           LoadConfigInt(confReader, "l3afd", "max-nf-restart-count"),
		MaxNFsAttachCount:           LoadConfigInt(confReader, "l3afd", "max-nfs-attach-count"),
		BpfChainingEnabled:          LoadOptionalConfigBool(confReader, "l3afd", "bpf-chaining-enabled", true),
		MetricsAddr:                 LoadConfigString(confReader, "web", "metrics-addr"),
		KFPollInterval:              LoadOptionalConfigDuration(confReader, "web", "kf-poll-interval", 30*time.Second),
		NMetricSamples:              LoadOptionalConfigInt(confReader, "web", "n-metric-samples", 20),
		ShutdownTimeout:             LoadConfigDuration(confReader, "l3afd", "shutdown-timeout"),
		AdmindHost:                  LoadConfigString(confReader, "admind", "host"),
		AdmindUsername:              LoadConfigString(confReader, "admind", "username"),
		AdmindApiKey:                LoadConfigString(confReader, "admind", "api-key"),
		AdmindGroupID:               LoadConfigInt(confReader, "admind", "group-id"),
		AdmindApiEnabled:            LoadOptionalConfigBool(confReader, "admind", "api-enabled", true),
		XDPRootProgramName:          LoadOptionalConfigString(confReader, "xdp-root-program", "name", "xdp_root"),
		XDPRootProgramArtifact:      LoadOptionalConfigString(confReader, "xdp-root-program", "artifact", "l3af_xdp_root.tar.gz"),
		XDPRootProgramMapName:       LoadOptionalConfigString(confReader, "xdp-root-program", "ingress-map-name", "/sys/fs/bpf/xdp_root_array"),
		XDPRootProgramCommand:       LoadOptionalConfigString(confReader, "xdp-root-program", "command", "xdp_root"),
		XDPRootProgramVersion:       LoadOptionalConfigString(confReader, "xdp-root-program", "version", "1.01"),
		XDPRootProgramIsUserProgram: LoadOptionalConfigBool(confReader, "xdp-root-program", "is-user-program", false),
		TCRootProgramName:           LoadOptionalConfigString(confReader, "tc-root-program", "name", "tc_root"),
		TCRootProgramArtifact:       LoadOptionalConfigString(confReader, "tc-root-program", "artifact", "l3af_tc_root.tar.gz"),
		TCRootProgramIngressMapName: LoadOptionalConfigString(confReader, "tc-root-program", "ingress-map-name", "/sys/fs/bpf/tc/globals/tc_ingress_root_array"),
		TCRootProgramEgressMapName:  LoadOptionalConfigString(confReader, "tc-root-program", "egress-map-name", "/sys/fs/bpf/tc/globals/tc_egress_root_array"),
		TCRootProgramCommand:        LoadOptionalConfigString(confReader, "tc-root-program", "command", "tc_root"),
		TCRootProgramVersion:        LoadOptionalConfigString(confReader, "tc-root-program", "version", "1.0"),
		TCRootProgramIsUserProgram:  LoadOptionalConfigBool(confReader, "tc-root-program", "is-user-program", false),
		EBPFChainDebugAddr:          LoadOptionalConfigString(confReader, "ebpf-chain-debug", "addr", "0.0.0.0:8899"),
		EBPFChainDebugEnabled:       LoadOptionalConfigBool(confReader, "ebpf-chain-debug", "enabled", false),
		L3afConfigsgRPCAddr:         LoadOptionalConfigString(confReader, "l3af-configs", "rpc-addr", "localhost:58898"),
		L3afConfigsRestAPIAddr:      LoadOptionalConfigString(confReader, "l3af-configs", "restapi-addr", "localhost:3000"),
	}, nil
}
