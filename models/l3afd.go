// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package models

// l3afd constants
const (
	Enabled  = "enabled"
	Disabled = "disabled"

	StartType = "start"
	StopType  = "stop"

	XDPType = "xdp"
	TCType  = "tc"

	IngressType    = "ingress"
	EgressType     = "egress"
	XDPIngressType = "xdpingress"
)

type L3afDNFArgs map[string]interface{}

// BPFProgram defines BPF Program for specific host
type BPFProgram struct {
	ID                int                 `json:"id"`                    // Program id
	Name              string              `json:"name"`                  // Name of the BPF program
	SeqID             int                 `json:"seq_id"`                // Sequence position in the chain
	Artifact          string              `json:"artifact"`              // Artifact file name
	MapName           string              `json:"map_name"`              // BPF map to store next program fd
	CmdStart          string              `json:"cmd_start"`             // Program start command
	CmdStop           string              `json:"cmd_stop"`              // Program stop command
	CmdStatus         string              `json:"cmd_status"`            // Program status command
	CmdConfig         string              `json:"cmd_config"`            // Program config providing command
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
	MapArgs           L3afDNFArgs         `json:"map_args"`              // Config BPF Map of arguments
	ConfigArgs        L3afDNFArgs         `json:"config_args"`           // Map of arguments to config command
	MonitorMaps       []L3afDNFMetricsMap `json:"monitor_maps"`          // Metrics BPF maps
	EPRURL            string              `json:"ebpf_package_repo_url"` // Download url for Program
}

// L3afDNFMetricsMap defines BPF map
type L3afDNFMetricsMap struct {
	Name       string `json:"name"`       // BPF map name
	Key        int    `json:"key"`        // Index of the bpf map
	Aggregator string `json:"aggregator"` // Aggregation function names
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
}
