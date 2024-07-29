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

const (
	ENV_PROD = "PROD"
)

type Config struct {
	PIDFilename         string
	DataCenter          string
	BPFDir              string
	BPFLogDir           string
	MinKernelMajorVer   int
	MinKernelMinorVer   int
	EBPFRepoURL         string
	HttpClientTimeout   time.Duration
	MaxEBPFReStartCount int
	Environment         string
	BpfMapDefaultPath   string
	// Flag to enable chaining with root program
	BpfChainingEnabled bool
	RestartDataFile    string

	FileLogLocation   string
	FileLogMaxSize    int
	FileLogMaxBackups int
	FileLogMaxAge     int

	// stats
	// Prometheus endpoint for pull/scrape the metrics.
	MetricsAddr      string
	EBPFPollInterval time.Duration
	NMetricSamples   int

	ShutdownTimeout time.Duration

	SwaggerApiEnabled bool

	// XDP Root program details.
	XDPRootPackageName       string
	XDPRootArtifact          string
	XDPRootMapName           string
	XDPRootCommand           string
	XDPRootVersion           string
	XDPRootObjectFile        string
	XDPRootEntryFunctionName string

	// TC Root program details.
	TCRootPackageName              string
	TCRootArtifact                 string
	TCRootIngressMapName           string
	TCRootEgressMapName            string
	TCRootCommand                  string
	TCRootVersion                  string
	TCRootIngressObjectFile        string
	TCRootEgressObjectFile         string
	TCRootIngressEntryFunctionName string
	TCRootEgressEntryFunctionName  string

	// ebpf chain details
	EBPFChainDebugAddr    string
	EBPFChainDebugEnabled bool

	// l3af configs to listen addrs
	L3afConfigsRestAPIAddr string

	// l3af config store
	L3afConfigStoreFileName string

	// mTLS
	MTLSEnabled               bool
	MTLSMinVersion            uint16
	MTLSCertDir               string
	MTLSCACertFilename        string
	MTLSServerCertFilename    string
	MTLSServerKeyFilename     string
	MTLSCertExpiryWarningDays int
	MTLSSANMatchRules         []string
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
		PIDFilename:                    LoadConfigString(confReader, "l3afd", "pid-file"),
		DataCenter:                     LoadConfigString(confReader, "l3afd", "datacenter"),
		BPFDir:                         LoadConfigString(confReader, "l3afd", "bpf-dir"),
		BPFLogDir:                      LoadOptionalConfigString(confReader, "l3afd", "bpf-log-dir", ""),
		MinKernelMajorVer:              LoadOptionalConfigInt(confReader, "l3afd", "kernel-major-version", 5),
		MinKernelMinorVer:              LoadOptionalConfigInt(confReader, "l3afd", "kernel-minor-version", 15),
		FileLogLocation:                LoadOptionalConfigString(confReader, "l3afd", "file-log-location", ""),
		FileLogMaxSize:                 LoadOptionalConfigInt(confReader, "l3afd", "file-log-max-size", 100),
		FileLogMaxBackups:              LoadOptionalConfigInt(confReader, "l3afd", "file-log-max-backups", 20),
		FileLogMaxAge:                  LoadOptionalConfigInt(confReader, "l3afd", "file-log-max-age", 60),
		EBPFRepoURL:                    LoadConfigString(confReader, "ebpf-repo", "url"),
		HttpClientTimeout:              LoadOptionalConfigDuration(confReader, "l3afd", "http-client-timeout", 30*time.Second),
		MaxEBPFReStartCount:            LoadOptionalConfigInt(confReader, "l3afd", "max-ebpf-restart-count", 3),
		BpfChainingEnabled:             LoadConfigBool(confReader, "l3afd", "bpf-chaining-enabled"),
		RestartDataFile:                LoadOptionalConfigString(confReader, "l3afd", "RestartDataFile", "/var/l3afd/l3af_meta.json"),
		MetricsAddr:                    LoadConfigString(confReader, "web", "metrics-addr"),
		EBPFPollInterval:               LoadOptionalConfigDuration(confReader, "web", "ebpf-poll-interval", 30*time.Second),
		NMetricSamples:                 LoadOptionalConfigInt(confReader, "web", "n-metric-samples", 20),
		ShutdownTimeout:                LoadOptionalConfigDuration(confReader, "l3afd", "shutdown-timeout", 25*time.Second),
		SwaggerApiEnabled:              LoadOptionalConfigBool(confReader, "l3afd", "swagger-api-enabled", false),
		Environment:                    LoadOptionalConfigString(confReader, "l3afd", "environment", ENV_PROD),
		BpfMapDefaultPath:              LoadConfigString(confReader, "l3afd", "BpfMapDefaultPath"),
		XDPRootPackageName:             loadXDPRootPackageName(confReader),
		XDPRootArtifact:                loadXDPRootArtifact(confReader),
		XDPRootMapName:                 loadXDPRootIngressMapName(confReader),
		XDPRootCommand:                 loadXDPRootCommand(confReader),
		XDPRootVersion:                 loadXDPRootVersion(confReader),
		XDPRootObjectFile:              LoadOptionalConfigString(confReader, "xdp-root", "object-file", "xdp_root.bpf.o"),
		XDPRootEntryFunctionName:       LoadOptionalConfigString(confReader, "xdp-root", "entry-function-name", "xdp_root"),
		TCRootPackageName:              loadTCRootPackageName(confReader),
		TCRootArtifact:                 loadTCRootArtifact(confReader),
		TCRootIngressMapName:           loadTCRootIngressMapName(confReader),
		TCRootEgressMapName:            loadTCRootEgressMapName(confReader),
		TCRootCommand:                  loadTCRootCommand(confReader),
		TCRootVersion:                  loadTCRootVersion(confReader),
		TCRootIngressObjectFile:        LoadOptionalConfigString(confReader, "tc-root", "ingress-object-file", "tc_root_ingress.bpf.o"),
		TCRootEgressObjectFile:         LoadOptionalConfigString(confReader, "tc-root", "egress-object-file", "tc_root_egress.bpf.o"),
		TCRootIngressEntryFunctionName: LoadOptionalConfigString(confReader, "tc-root", "ingress-entry-function-name", "tc_ingress_root"),
		TCRootEgressEntryFunctionName:  LoadOptionalConfigString(confReader, "tc-root", "egress-entry-function-name", "tc_egress_root"),
		EBPFChainDebugAddr:             LoadOptionalConfigString(confReader, "ebpf-chain-debug", "addr", "localhost:8899"),
		EBPFChainDebugEnabled:          LoadOptionalConfigBool(confReader, "ebpf-chain-debug", "enabled", false),
		L3afConfigsRestAPIAddr:         LoadOptionalConfigString(confReader, "l3af-configs", "restapi-addr", "localhost:53000"),
		L3afConfigStoreFileName:        LoadConfigString(confReader, "l3af-config-store", "filename"),
		MTLSEnabled:                    LoadOptionalConfigBool(confReader, "mtls", "enabled", true),
		MTLSMinVersion:                 minTLSVersion,
		MTLSCertDir:                    LoadOptionalConfigString(confReader, "mtls", "cert-dir", ""),
		MTLSCACertFilename:             LoadOptionalConfigString(confReader, "mtls", "cacert-filename", "ca.pem"),
		MTLSServerCertFilename:         LoadOptionalConfigString(confReader, "mtls", "server-cert-filename", "server.crt"),
		MTLSServerKeyFilename:          LoadOptionalConfigString(confReader, "mtls", "server-key-filename", "server.key"),
		MTLSCertExpiryWarningDays:      LoadOptionalConfigInt(confReader, "mtls", "cert-expiry-warning-days", 30),
		MTLSSANMatchRules:              strings.Split(LoadOptionalConfigString(confReader, "mtls", "san-match-rules", ""), ","),
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

func loadXDPRootPackageName(cfgRdr *config.Config) string {
	xdpRootPackageName := LoadOptionalConfigString(cfgRdr, "xdp-root-program", "name", "")
	if xdpRootPackageName == "" {
		xdpRootPackageName = LoadOptionalConfigString(cfgRdr, "xdp-root", "package-name", "xdp-root")
	}
	return xdpRootPackageName
}

func loadXDPRootArtifact(cfgRdr *config.Config) string {
	xdpRootArtifactName := LoadOptionalConfigString(cfgRdr, "xdp-root-program", "artifact", "")
	if xdpRootArtifactName == "" {
		xdpRootArtifactName = LoadOptionalConfigString(cfgRdr, "xdp-root", "artifact", "l3af_xdp_root.tar.gz")
	}
	return xdpRootArtifactName
}

func loadXDPRootIngressMapName(cfgRdr *config.Config) string {
	xdpRootIngressMapName := LoadOptionalConfigString(cfgRdr, "xdp-root-program", "ingress-map-name", "")
	if xdpRootIngressMapName == "" {
		xdpRootIngressMapName = LoadOptionalConfigString(cfgRdr, "xdp-root", "ingress-map-name", "xdp_root_array")
	}
	return xdpRootIngressMapName
}

func loadXDPRootCommand(cfgRdr *config.Config) string {
	xdpRootCommand := LoadOptionalConfigString(cfgRdr, "xdp-root-program", "command", "")
	if xdpRootCommand == "" {
		xdpRootCommand = LoadOptionalConfigString(cfgRdr, "xdp-root", "command", "xdp_root")
	}
	return xdpRootCommand
}

func loadXDPRootVersion(cfgRdr *config.Config) string {
	xdpRootVersion := LoadOptionalConfigString(cfgRdr, "xdp-root-program", "version", "")
	if xdpRootVersion == "" {
		xdpRootVersion = LoadOptionalConfigString(cfgRdr, "xdp-root", "version", "latest")
	}
	return xdpRootVersion
}

func loadTCRootPackageName(cfgRdr *config.Config) string {
	tcRootPackageName := LoadOptionalConfigString(cfgRdr, "tc-root-program", "name", "")
	if tcRootPackageName == "" {
		tcRootPackageName = LoadOptionalConfigString(cfgRdr, "tc-root", "package-name", "tc-root")
	}
	return tcRootPackageName
}

func loadTCRootArtifact(cfgRdr *config.Config) string {
	tcRootArtifactName := LoadOptionalConfigString(cfgRdr, "tc-root-program", "artifact", "")
	if tcRootArtifactName == "" {
		tcRootArtifactName = LoadOptionalConfigString(cfgRdr, "tc-root", "artifact", "l3af_tc_root.tar.gz")
	}
	return tcRootArtifactName
}

func loadTCRootIngressMapName(cfgRdr *config.Config) string {
	tcRootIngressMapName := LoadOptionalConfigString(cfgRdr, "tc-root-program", "ingress-map-name", "")
	if tcRootIngressMapName == "" {
		tcRootIngressMapName = LoadOptionalConfigString(cfgRdr, "tc-root", "ingress-map-name", "tc_ingress_root_array")
	}
	return tcRootIngressMapName
}

func loadTCRootEgressMapName(cfgRdr *config.Config) string {
	tcRootEgressMapName := LoadOptionalConfigString(cfgRdr, "tc-root-program", "egress-map-name", "")
	if tcRootEgressMapName == "" {
		tcRootEgressMapName = LoadOptionalConfigString(cfgRdr, "tc-root", "egress-map-name", "tc_egress_root_array")
	}
	return tcRootEgressMapName
}

func loadTCRootCommand(cfgRdr *config.Config) string {
	tcRootCommand := LoadOptionalConfigString(cfgRdr, "tc-root-program", "command", "")
	if tcRootCommand == "" {
		tcRootCommand = LoadOptionalConfigString(cfgRdr, "tc-root", "command", "tc_root")
	}
	return tcRootCommand
}

func loadTCRootVersion(cfgRdr *config.Config) string {
	tcRootVersion := LoadOptionalConfigString(cfgRdr, "tc-root-program", "version", "")
	if tcRootVersion == "" {
		tcRootVersion = LoadOptionalConfigString(cfgRdr, "tc-root", "version", "latest")
	}
	return tcRootVersion
}
