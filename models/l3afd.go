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
	ID             int                 `json:"id"`
	Name           string              `json:"name"`
	SeqID          int                 `json:"seq_id"`
	Artifact       string              `json:"artifact"`
	MapName        string              `json:"map_name"`
	CmdStart       string              `json:"cmd_start"`
	CmdStop        string              `json:"cmd_stop"`
	CmdStatus      string              `json:"cmd_status"`
	CmdConfig      string              `json:"cmd_config"`
	Version        string              `json:"version"`
	IsUserProgram  bool                `json:"is_user_program"`
	IsPlugin       bool                `json:"is_plugin"`
	CPU            int                 `json:"cpu"`
	Memory         int                 `json:"memory"`
	AdminStatus    string              `json:"admin_status"`
	EBPFType       string              `json:"ebpf_type"`
	RulesFile      string              `json:"rules_file"`
	Rules          string              `json:"rules"`
	ConfigFilePath string              `json:"config_file_path"`
	CfgVersion     int                 `json:"cfg_version"`
	StartArgs      L3afDNFArgs         `json:"start_args"`
	StopArgs       L3afDNFArgs         `json:"stop_args"`
	StatusArgs     L3afDNFArgs         `json:"status_args"`
	MapArgs        L3afDNFArgs         `json:"map_args"`
	ConfigArgs     L3afDNFArgs         `json:"config_args"`
	MonitorMaps    []L3afDNFMetricsMap `json:"monitor_maps"`
}

// L3afDNFConfigDetail defines map of host specific NF configurations
type L3afDNFConfigDetail struct {
	HostName          string                                    `json:"host_name"`
	HostProgramConfig map[string]map[string]map[int]*BPFProgram `json:"bpf_programs"` // map of iface name (string), map of direction (igress/egress) and seq_id
}

// L3afDNFMetricsMap defines KF map for CDB
type L3afDNFMetricsMap struct {
	Name       string `json:"name"`
	Key        int    `json:"key"`
	Aggregator string `json:"aggregator"`
}

type L3afBPFPrograms struct {
	HostName    string       `json:"host_name"`    // host name or pod name
	Iface       string       `json:"iface"`        // Interface name
	BpfPrograms *BPFPrograms `json:"bpf_programs"` // list of bpf programs
}

type BPFPrograms struct {
	XdpIngress []*BPFProgram `json:"xdp_ingress"` // list of xdp bpf programs
	TCIngress  []*BPFProgram `json:"tc_ingress"`  // list of tc ingress bpf programs
	TCEgress   []*BPFProgram `json:"tc_egress"`   // list of tc egress bpf programs
}
