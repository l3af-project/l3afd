// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package config provides primitives for l3afd configuration ( i.e. l3afd.cfg) file.
package config

import (
	"crypto/tls"
	"fmt"
	"strings"
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

	SwaggerApiEnabled bool

	// Admin API endpoint config for registering l3afd.
	AdmindHost       string
	AdmindUsername   string
	AdmindApiKey     string
	AdmindGroupID    int
	AdmindApiEnabled bool

	// XDP Root program details.
	XDPRootProgramName              string
	XDPRootProgramArtifact          string
	XDPRootProgramMapName           string
	XDPRootProgramCommand           string
	XDPRootProgramVersion           string
	XDPRootProgramUserProgramDaemon bool

	// TC Root program details.
	TCRootProgramName              string
	TCRootProgramArtifact          string
	TCRootProgramIngressMapName    string
	TCRootProgramEgressMapName     string
	TCRootProgramCommand           string
	TCRootProgramVersion           string
	TCRootProgramUserProgramDaemon bool

	// ebpf chain details
	EBPFChainDebugAddr    string
	EBPFChainDebugEnabled bool

	// l3af configs to listen addrs
	L3afConfigsRestAPIAddr string

	// l3af config store
	L3afConfigStoreFileName string

	// mTLS
	MTLSEnabled            bool
	MTLSMinVersion         uint16
	MTLSCertDir            string
	MTLSCACertFilename     string
	MTLSServerCertFilename string
	MTLSServerKeyFilename  string
}

// ReadConfig - Initializes configuration from file
func ReadConfig(configPath string) (*Config, error) {

	log.Info().Msgf("Reading configuration from: %s", configPath)
	confReader, configErr := config.ReadDefault(configPath)
	if configErr != nil {
		log.Fatal().Err(configErr).Msgf("Could not open config file %q", configPath)
	}
	minTLSVersion, err := loadTLSVersion(confReader, "min-tls-version")
	if err != nil {
		return nil, err
	}

	return &Config{
		PIDFilename:                     LoadConfigString(confReader, "l3afd", "pid-file"),
		DataCenter:                      LoadConfigString(confReader, "l3afd", "datacenter"),
		BPFDir:                          LoadConfigString(confReader, "l3afd", "bpf-dir"),
		BPFLogDir:                       LoadConfigString(confReader, "l3afd", "bpf-log-dir"),
		MinKernelMajorVer:               LoadConfigInt(confReader, "l3afd", "kernel-major-version"),
		MinKernelMinorVer:               LoadConfigInt(confReader, "l3afd", "kernel-minor-version"),
		KFRepoURL:                       LoadConfigString(confReader, "kf-repo", "url"),
		HttpClientTimeout:               LoadConfigDuration(confReader, "l3afd", "http-client-timeout"),
		MaxNFReStartCount:               LoadConfigInt(confReader, "l3afd", "max-nf-restart-count"),
		MaxNFsAttachCount:               LoadConfigInt(confReader, "l3afd", "max-nfs-attach-count"),
		BpfChainingEnabled:              LoadOptionalConfigBool(confReader, "l3afd", "bpf-chaining-enabled", true),
		MetricsAddr:                     LoadConfigString(confReader, "web", "metrics-addr"),
		KFPollInterval:                  LoadOptionalConfigDuration(confReader, "web", "kf-poll-interval", 30*time.Second),
		NMetricSamples:                  LoadOptionalConfigInt(confReader, "web", "n-metric-samples", 20),
		ShutdownTimeout:                 LoadConfigDuration(confReader, "l3afd", "shutdown-timeout"),
		SwaggerApiEnabled:               LoadOptionalConfigBool(confReader, "l3afd", "swagger-api-enabled", false),
		AdmindHost:                      LoadConfigString(confReader, "admind", "host"),
		AdmindUsername:                  LoadConfigString(confReader, "admind", "username"),
		AdmindApiKey:                    LoadConfigString(confReader, "admind", "api-key"),
		AdmindGroupID:                   LoadConfigInt(confReader, "admind", "group-id"),
		AdmindApiEnabled:                LoadOptionalConfigBool(confReader, "admind", "api-enabled", true),
		XDPRootProgramName:              LoadOptionalConfigString(confReader, "xdp-root-program", "name", "xdp_root"),
		XDPRootProgramArtifact:          LoadOptionalConfigString(confReader, "xdp-root-program", "artifact", "l3af_xdp_root.tar.gz"),
		XDPRootProgramMapName:           LoadOptionalConfigString(confReader, "xdp-root-program", "ingress-map-name", "/sys/fs/bpf/xdp_root_array"),
		XDPRootProgramCommand:           LoadOptionalConfigString(confReader, "xdp-root-program", "command", "xdp_root"),
		XDPRootProgramVersion:           LoadOptionalConfigString(confReader, "xdp-root-program", "version", "1.01"),
		XDPRootProgramUserProgramDaemon: LoadOptionalConfigBool(confReader, "xdp-root-program", "user-program-daemon", false),
		TCRootProgramName:               LoadOptionalConfigString(confReader, "tc-root-program", "name", "tc_root"),
		TCRootProgramArtifact:           LoadOptionalConfigString(confReader, "tc-root-program", "artifact", "l3af_tc_root.tar.gz"),
		TCRootProgramIngressMapName:     LoadOptionalConfigString(confReader, "tc-root-program", "ingress-map-name", "/sys/fs/bpf/tc/globals/tc_ingress_root_array"),
		TCRootProgramEgressMapName:      LoadOptionalConfigString(confReader, "tc-root-program", "egress-map-name", "/sys/fs/bpf/tc/globals/tc_egress_root_array"),
		TCRootProgramCommand:            LoadOptionalConfigString(confReader, "tc-root-program", "command", "tc_root"),
		TCRootProgramVersion:            LoadOptionalConfigString(confReader, "tc-root-program", "version", "1.0"),
		TCRootProgramUserProgramDaemon:  LoadOptionalConfigBool(confReader, "tc-root-program", "user-program-daemon", false),
		EBPFChainDebugAddr:              LoadOptionalConfigString(confReader, "ebpf-chain-debug", "addr", "0.0.0.0:8899"),
		EBPFChainDebugEnabled:           LoadOptionalConfigBool(confReader, "ebpf-chain-debug", "enabled", false),
		L3afConfigsRestAPIAddr:          LoadOptionalConfigString(confReader, "l3af-configs", "restapi-addr", "localhost:53000"),
		L3afConfigStoreFileName:         LoadOptionalConfigString(confReader, "l3af-config-store", "filename", "/etc/l3afd/l3af-config.json"),
		MTLSEnabled:                     LoadOptionalConfigBool(confReader, "mtls", "enabled", true),
		MTLSMinVersion:                  minTLSVersion,
		MTLSCertDir:                     LoadOptionalConfigString(confReader, "mtls", "cert-dir", "/etc/l3afd/certs"),
		MTLSCACertFilename:              LoadOptionalConfigString(confReader, "mtls", "cacert-filename", "ca.pem"),
		MTLSServerCertFilename:          LoadOptionalConfigString(confReader, "mtls", "server-cert-filename", "server.crt"),
		MTLSServerKeyFilename:           LoadOptionalConfigString(confReader, "mtls", "server-key-filename", "server.key"),
	}, nil
}

func loadTLSVersion(cfgRdr *config.Config, fieldName string) (uint16, error) {
	ver := strings.TrimSpace(LoadOptionalConfigString(cfgRdr, "mTLS", fieldName, "TLS_1.3"))
	switch ver {
	case "", "Default", "default":
		return tls.VersionTLS13, nil
	case "TLS_1.2":
		return tls.VersionTLS12, nil
	case "TLS_1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("Unsupported TLS version: \"" + ver + "\". Use: TLS_1.{2,3}.")
	}
}
