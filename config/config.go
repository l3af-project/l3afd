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

	// stats
	// Prometheus endpoint for pull/scrape the metrics.
	MetricsAddr      string
	EBPFPollInterval time.Duration
	NMetricSamples   int

	ShutdownTimeout time.Duration

	SwaggerApiEnabled bool

	// XDP Root program details.
	XDPRootProgramName     string
	XDPRootProgramArtifact string
	XDPRootProgramMapName  string
	XDPRootProgramCommand  string
	XDPRootProgramVersion  string

	// TC Root program details.
	TCRootProgramName           string
	TCRootProgramArtifact       string
	TCRootProgramIngressMapName string
	TCRootProgramEgressMapName  string
	TCRootProgramCommand        string
	TCRootProgramVersion        string

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
		PIDFilename:                 LoadConfigString(confReader, "l3afd", "pid-file"),
		DataCenter:                  LoadConfigString(confReader, "l3afd", "datacenter"),
		BPFDir:                      LoadConfigString(confReader, "l3afd", "bpf-dir"),
		BPFLogDir:                   LoadOptionalConfigString(confReader, "l3afd", "bpf-log-dir", ""),
		MinKernelMajorVer:           LoadOptionalConfigInt(confReader, "l3afd", "kernel-major-version", 5),
		MinKernelMinorVer:           LoadOptionalConfigInt(confReader, "l3afd", "kernel-minor-version", 1),
		EBPFRepoURL:                 LoadConfigString(confReader, "ebpf-repo", "url"),
		HttpClientTimeout:           LoadOptionalConfigDuration(confReader, "l3afd", "http-client-timeout", 10*time.Second),
		MaxEBPFReStartCount:         LoadOptionalConfigInt(confReader, "l3afd", "max-ebpf-restart-count", 3),
		BpfChainingEnabled:          LoadConfigBool(confReader, "l3afd", "bpf-chaining-enabled"),
		MetricsAddr:                 LoadConfigString(confReader, "web", "metrics-addr"),
		EBPFPollInterval:            LoadOptionalConfigDuration(confReader, "web", "ebpf-poll-interval", 30*time.Second),
		NMetricSamples:              LoadOptionalConfigInt(confReader, "web", "n-metric-samples", 20),
		ShutdownTimeout:             LoadOptionalConfigDuration(confReader, "l3afd", "shutdown-timeout", 5*time.Second),
		SwaggerApiEnabled:           LoadOptionalConfigBool(confReader, "l3afd", "swagger-api-enabled", false),
		Environment:                 LoadOptionalConfigString(confReader, "l3afd", "environment", ENV_PROD),
		BpfMapDefaultPath:           LoadConfigString(confReader, "l3afd", "BpfMapDefaultPath"),
		XDPRootProgramName:          LoadOptionalConfigString(confReader, "xdp-root-program", "name", "xdp-root"),
		XDPRootProgramArtifact:      LoadOptionalConfigString(confReader, "xdp-root-program", "artifact", "l3af_xdp_root.tar.gz"),
		XDPRootProgramMapName:       LoadOptionalConfigString(confReader, "xdp-root-program", "ingress-map-name", "xdp_root_array"),
		XDPRootProgramCommand:       LoadOptionalConfigString(confReader, "xdp-root-program", "command", "xdp_root"),
		XDPRootProgramVersion:       LoadOptionalConfigString(confReader, "xdp-root-program", "version", "latest"),
		TCRootProgramName:           LoadOptionalConfigString(confReader, "tc-root-program", "name", "tc-root"),
		TCRootProgramArtifact:       LoadOptionalConfigString(confReader, "tc-root-program", "artifact", "l3af_tc_root.tar.gz"),
		TCRootProgramIngressMapName: LoadOptionalConfigString(confReader, "tc-root-program", "ingress-map-name", "tc/globals/tc_ingress_root_array"),
		TCRootProgramEgressMapName:  LoadOptionalConfigString(confReader, "tc-root-program", "egress-map-name", "tc/globals/tc_egress_root_array"),
		TCRootProgramCommand:        LoadOptionalConfigString(confReader, "tc-root-program", "command", "tc_root"),
		TCRootProgramVersion:        LoadOptionalConfigString(confReader, "tc-root-program", "version", "latest"),
		EBPFChainDebugAddr:          LoadOptionalConfigString(confReader, "ebpf-chain-debug", "addr", "localhost:8899"),
		EBPFChainDebugEnabled:       LoadOptionalConfigBool(confReader, "ebpf-chain-debug", "enabled", false),
		L3afConfigsRestAPIAddr:      LoadOptionalConfigString(confReader, "l3af-configs", "restapi-addr", "localhost:53000"),
		L3afConfigStoreFileName:     LoadConfigString(confReader, "l3af-config-store", "filename"),
		MTLSEnabled:                 LoadOptionalConfigBool(confReader, "mtls", "enabled", true),
		MTLSMinVersion:              minTLSVersion,
		MTLSCertDir:                 LoadOptionalConfigString(confReader, "mtls", "cert-dir", ""),
		MTLSCACertFilename:          LoadOptionalConfigString(confReader, "mtls", "cacert-filename", "ca.pem"),
		MTLSServerCertFilename:      LoadOptionalConfigString(confReader, "mtls", "server-cert-filename", "server.crt"),
		MTLSServerKeyFilename:       LoadOptionalConfigString(confReader, "mtls", "server-key-filename", "server.key"),
		MTLSCertExpiryWarningDays:   LoadOptionalConfigInt(confReader, "mtls", "cert-expiry-warning-days", 30),
		MTLSSANMatchRules:           strings.Split(LoadOptionalConfigString(confReader, "mtls", "san-match-rules", ""), ","),
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
