// Package config provides primitives for l3afd configuration ( i.e. l3afd.cfg) file.
package config

import (
	"time"

	"tbd/go-shared/logs"
	"tbd/go-shared/util"
	"tbd/goconfig/config"
)

type Config struct {
	PIDFilename       string
	DataCenter        string
	CDBFilename       string
	BPFDir            string
	BPFLogDir         string
	MinKernelMajorVer int
	MinKernelMinorVer int
	ProximityUrl      string
	HttpClientTimeout time.Duration
	MaxNFReStartCount int
	MaxNFsAttachCount int

	// Flag to enable chaining with root program
	BpfChainingEnabled bool

	// Delay added in seconds between stop and start xdp programs so that all the in-memory maps are released
	BpfDelayTime       int

	// stats
	// Prometheus endpoint for pull/scrape the metrics.
	MetricsAddr string
	PollInterval time.Duration

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
}

//Initializes configuration from file
func ReadConfig(configPath string) (*Config, error) {

	logs.Infof("Reading configuration from: %s", configPath)
	confReader, configErr := config.ReadDefault(configPath)
	logs.IfFatalLogf(configErr, "Could not open config file %q", configPath)

	return &Config{
		PIDFilename:                 util.LoadConfigString(confReader, "l3afd", "pid-file"),
		DataCenter:                  util.LoadConfigString(confReader, "l3afd", "datacenter"),
		CDBFilename:                 util.LoadConfigString(confReader, "l3afd", "cdb-file"),
		BPFDir:                      util.LoadConfigString(confReader, "l3afd", "bpf-dir"),
		BPFLogDir:                   util.LoadConfigString(confReader, "l3afd", "bpf-log-dir"),
		MinKernelMajorVer:           util.LoadConfigInt(confReader, "l3afd", "kernel-major-version"),
		MinKernelMinorVer:           util.LoadConfigInt(confReader, "l3afd", "kernel-minor-version"),
		ProximityUrl:                util.LoadConfigString(confReader, "proximity", "url"),
		HttpClientTimeout:           util.LoadConfigDuration(confReader, "l3afd", "http-client-timeout"),
		MaxNFReStartCount:           util.LoadConfigInt(confReader, "l3afd", "max-nf-restart-count"),
		MaxNFsAttachCount:           util.LoadConfigInt(confReader, "l3afd", "max-nfs-attach-count"),
		BpfChainingEnabled:          util.LoadOptionalConfigBool(confReader, "l3afd", "bpf-chaining-enabled", true),
		BpfDelayTime:                util.LoadOptionalConfigInt(confReader, "l3afd", "bpf-delay-time", 5),
		MetricsAddr:                 util.LoadConfigString(confReader, "web", "metrics-addr"),
		PollInterval:                util.LoadOptionalConfigDuration(confReader, "web", "poll-interval", 10),
		ShutdownTimeout:             util.LoadConfigDuration(confReader, "l3afd", "shutdown-timeout"),
		AdmindHost:                  util.LoadConfigString(confReader, "admind", "host"),
		AdmindUsername:              util.LoadConfigString(confReader, "admind", "username"),
		AdmindApiKey:                util.LoadConfigString(confReader, "admind", "api-key"),
		AdmindGroupID:               util.LoadConfigInt(confReader, "admind", "group-id"),
		AdmindApiEnabled:            util.LoadOptionalConfigBool(confReader, "admind", "api-enabled",true),
		XDPRootProgramName:          util.LoadOptionalConfigString(confReader, "xdp-root-program", "name", "xdp_root"),
		XDPRootProgramArtifact:      util.LoadOptionalConfigString(confReader, "xdp-root-program", "artifact", "l3af_xdp_root.tar.gz"),
		XDPRootProgramMapName:       util.LoadOptionalConfigString(confReader, "xdp-root-program", "ingress-map-name", "/sys/fs/bpf/xdp_root_array"),
		XDPRootProgramCommand:       util.LoadOptionalConfigString(confReader, "xdp-root-program", "command", "xdp_root"),
		XDPRootProgramVersion:       util.LoadOptionalConfigString(confReader, "xdp-root-program", "version", "1.01"),
		XDPRootProgramIsUserProgram: util.LoadOptionalConfigBool(confReader, "xdp-root-program", "is-user-program", false),
		TCRootProgramName:           util.LoadOptionalConfigString(confReader, "tc-root-program", "name", "tc_root"),
		TCRootProgramArtifact:       util.LoadOptionalConfigString(confReader, "tc-root-program", "artifact", "l3af_tc_root.tar.gz"),
		TCRootProgramIngressMapName: util.LoadOptionalConfigString(confReader, "tc-root-program", "ingress-map-name", "/sys/fs/bpf/tc/globals/tc_ingress_root_array"),
		TCRootProgramEgressMapName:  util.LoadOptionalConfigString(confReader, "tc-root-program", "egress-map-name", "/sys/fs/bpf/tc/globals/tc_egress_root_array"),
		TCRootProgramCommand:        util.LoadOptionalConfigString(confReader, "tc-root-program", "command", "tc_root"),
		TCRootProgramVersion:        util.LoadOptionalConfigString(confReader, "tc-root-program", "version", "1.0"),
		TCRootProgramIsUserProgram:  util.LoadOptionalConfigBool(confReader, "tc-root-program", "is-user-program", false),
	}, nil
}
