package models

// l3afd constants
const (
	Enabled  = "enabled"
	Disabled = "disabled"

	StartType  = "start"
	StopType   = "stop"
	StatusType = "status"
	MapType    = "map"
	ConfigType = "config"

	XDPType = "xdp"
	TCType  = "tc"

	IngressType    = "ingress"
	EgressType     = "egress"
	XDPIngressType = "xdpingress"
)

// L3afDNFArgs defines NF program arguments
type L3afDNFArgs struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Equal compares two L3afDNFArgs for equality
func (l *L3afDNFArgs) Equal(arg L3afDNFArgs) bool {
	if l.Key != arg.Key || l.Value != arg.Value {
		return false
	}
	return true
}

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
	StartArgs      []L3afDNFArgs       `json:"start_args"`
	StopArgs       []L3afDNFArgs       `json:"stop_args"`
	StatusArgs     []L3afDNFArgs       `json:"status_args"`
	MapArgs        []L3afDNFArgs       `json:"map_args"`
	ConfigArgs     []L3afDNFArgs       `json:"config_args"`
	MonitorMaps    []L3afDNFMetricsMap `json:"monitor_maps"`
}

// AddStartArgs adds start arguments to a BPFProgram
func (bpf *BPFProgram) AddStartArgs(args L3afDNFArgs) []L3afDNFArgs {
	bpf.StartArgs = append(bpf.StartArgs, args)
	return bpf.StartArgs
}

// AddStopArgs adds stop arguments to a BPFProgram
func (bpf *BPFProgram) AddStopArgs(args L3afDNFArgs) []L3afDNFArgs {
	bpf.StopArgs = append(bpf.StopArgs, args)
	return bpf.StopArgs
}

// AddStatusArgs adds status arguments to a BPFProgram
func (bpf *BPFProgram) AddStatusArgs(args L3afDNFArgs) []L3afDNFArgs {
	bpf.StatusArgs = append(bpf.StatusArgs, args)
	return bpf.StatusArgs
}

// AddMapArgs adds map arguments to a BPFProgram
func (bpf *BPFProgram) AddMapArgs(args L3afDNFArgs) []L3afDNFArgs {
	bpf.MapArgs = append(bpf.MapArgs, args)
	return bpf.MapArgs
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
