// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package models

// l3afd constants
const (
	Enabled  = "enabled"
	Disabled = "disabled"

	StartType  = "start"
	StopType   = "stop"
	UpdateType = "update"

	XDPType = "xdp"
	TCType  = "tc"

	IngressType    = "ingress"
	EgressType     = "egress"
	XDPIngressType = "xdpingress"
	TCMapPinPath   = "tc/globals"
)

type L3afDNFArgs map[string]interface{}

// BPFProgram defines BPF Program for specific host
type BPFProgram struct {
	ID                int                 `json:"id"`                    // Program id
	Name              string              `json:"name"`                  // Name of the BPF program package
	SeqID             int                 `json:"seq_id"`                // Sequence position in the chain
	Artifact          string              `json:"artifact"`              // Artifact file name
	MapName           string              `json:"map_name"`              // BPF map to store next program fd
	CmdStart          string              `json:"cmd_start"`             // Program start command
	CmdStop           string              `json:"cmd_stop"`              // Program stop command
	CmdStatus         string              `json:"cmd_status"`            // Program status command
	CmdConfig         string              `json:"cmd_config"`            // Program config providing command
	CmdUpdate         string              `json:"cmd_update"`            // Program update config command
	Version           string              `json:"version"`               // Program version
	UserProgramDaemon bool                `json:"user_program_daemon"`   // User program daemon or not
	IsPlugin          bool                `json:"is_plugin"`             // User program is plugin or not
	CPU               int                 `json:"cpu"`                   // User program cpu limits
	Memory            int                 `json:"memory"`                // User program memory limits
	AdminStatus       string              `json:"admin_status"`          // Program admin status enabled or disabled
	ProgType          string              `json:"prog_type"`             // Program type XDP or TC
	RulesFile         string              `json:"rules_file"`            // Config rules file name
	Rules             string              `json:"rules"`                 // Config rules
	ConfigFilePath    string              `json:"config_file_path"`      // Config file location
	CfgVersion        int                 `json:"cfg_version"`           // Config version
	StartArgs         L3afDNFArgs         `json:"start_args"`            // Map of arguments to start command
	StopArgs          L3afDNFArgs         `json:"stop_args"`             // Map of arguments to stop command
	StatusArgs        L3afDNFArgs         `json:"status_args"`           // Map of arguments to status command
	UpdateArgs        L3afDNFArgs         `json:"update_args"`           // Map of arguments to update command
	MapArgs           []L3afDMapArg       `json:"map_args"`              // Config BPF Map of arguments
	ConfigArgs        L3afDNFArgs         `json:"config_args"`           // Map of arguments to config command
	MonitorMaps       []L3afDNFMetricsMap `json:"monitor_maps"`          // Metrics BPF maps
	EPRURL            string              `json:"ebpf_package_repo_url"` // Download url for Program
	ObjectFile        string              `json:"object_file"`           // Object file contains BPF code
	EntryFunctionName string              `json:"entry_function_name"`   // BPF entry function name to load
}

// L3afDNFMetricsMap defines BPF map
type L3afDNFMetricsMap struct {
	Name       string `json:"name"`       // BPF map name
	Key        int    `json:"key"`        // Index of the bpf map
	Aggregator string `json:"aggregator"` // Aggregation function names
}

// KeyValue defines struct for key and value
type KeyValue struct {
	Key   int `json:"key"`   // Key
	Value int `json:"value"` // Value
}

// L3afDMapArg defines map arg
type L3afDMapArg struct {
	Name string     `json:"name"` // BPF map name
	Args []KeyValue `json:"args"` // BPF map arguments
}

// L3afBPFPrograms defines configs for a node
type L3afBPFPrograms struct {
	HostName    string       `json:"host_name"`    // Host name or pod name
	Iface       string       `json:"iface"`        // Interface name
	BpfPrograms *BPFPrograms `json:"bpf_programs"` // List of bpf programs
}

// BPFPrograms for a node
type BPFPrograms struct {
	XDPIngress []*BPFProgram `json:"xdp_ingress"` // list of xdp ingress bpf programs
	TCIngress  []*BPFProgram `json:"tc_ingress"`  // list of tc ingress bpf programs
	TCEgress   []*BPFProgram `json:"tc_egress"`   // list of tc egress bpf programs
	Probes     []*BPFProgram `json:"probes"`      // list of probe bpf programs
}

// L3afBPFProgramNames defines names of Bpf programs on interface
type L3afBPFProgramNames struct {
	HostName        string           `json:"host_name"`    // Host name or pod name
	Iface           string           `json:"iface"`        // Interface name
	BpfProgramNames *BPFProgramNames `json:"bpf_programs"` // List of eBPF program names to remove
}

// BPFProgramNames defines names of eBPF programs on node
type BPFProgramNames struct {
	XDPIngress []string `json:"xdp_ingress"` // names of the XDP ingress eBPF programs
	TCIngress  []string `json:"tc_ingress"`  // names of the TC ingress eBPF programs
	TCEgress   []string `json:"tc_egress"`   // names of the TC egress eBPF programs
	Probes     []string `json:"probes"`      // names of the probe eBPF programs
}

type MetaColl struct {
	Programs []string
	Maps     []string
}

type MetaMetricsBPFMap struct {
	MapName    string
	Key        int
	Values     []float64
	Aggregator string
	LastValue  float64
}

type Label struct {
	Name  string
	Value string
}

type MetricVec struct {
	MetricName string
	Labels     []Label
	Value      float64
	Type       int32
}

type L3AFMetaData struct {
	Program           BPFProgram
	FilePath          string
	RestartCount      int
	PrevMapNamePath   string
	MapNamePath       string
	ProgID            uint32
	BpfMaps           []string
	MetricsBpfMaps    map[string]MetaMetricsBPFMap
	ProgMapCollection MetaColl
	ProgMapID         uint32
	PrevProgMapID     uint32
	XDPLink           bool
	UserProgramPID    int
}

type L3AFALLHOSTDATA struct {
	HostName       string
	HostInterfaces map[string]bool
	IngressXDPBpfs map[string][]*L3AFMetaData
	IngressTCBpfs  map[string][]*L3AFMetaData
	EgressTCBpfs   map[string][]*L3AFMetaData
	ProbesBpfs     []L3AFMetaData
	Ifaces         map[string]string
	AllStats       []MetricVec
	InRestart      bool
}

var CloseForRestart chan struct{}
