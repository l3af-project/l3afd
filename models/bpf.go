// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"github.com/cilium/ebpf"
	"github.com/l3af-project/l3afd/config"
)

// BPF defines run time details for BPFProgram.
type BPF interface {
	// Name returns the BPFProgram Package Name
	Name() string

	// Artifact returns the BPFProgram Artifact
	Artifact() string

	// MapName returns the map name of the BPFProgram
	MapName() string

	// ProgId returns the program ID of the BPFProgram
	ProgId() int

	// SeqId return the sequence ID of the BPFProgram
	SeqId() int

	// AdminStatus return the admin status of the BPFProgram
	AdminStatus() string

	// Version returns the version of the BPFProgram
	Version() string

	// RestartCount returns the restart count
	GetRestartCount() int

	// GetProgram return the underlying BPFProgram
	GetProgram() *BPFProgram

	// GetMapNamePath returns the MapNamePath
	GetMapNamePath() string

	// GetPrevMapNamePath returns the PrevMapNamePath
	GetPrevMapNamePath() string

	// AddToRestartCount increases the RestartCount by the passed value
	AddToRestartCount(value int)

	// UpdateAdminStatus updates the admin status of the BPFProgram to rhe passed string
	UpdateAdminStatus(value string)

	// UpdatesProgram updates the underlying BPFProgram to the passed BPFProgram struct
	UpdateProgram(value *BPFProgram)

	// UpdatePrevMapNamePath updates the PrevMapNamePath to the passed string.
	UpdatePrevMapNamePath(value string)

	// Stop returns the last error seen, but stops bpf program.
	// Clean up all map handles.
	// Verify next program pinned map file is removed
	Stop(ifaceName, direction string, chain bool) error

	// Start returns the last error seen, but starts bpf program.
	// Here initially prevprogmap entry is removed and passed to the bpf program
	// After starting the user program, will update the kernel progam fd into prevprogram map.
	// This method waits till prog Namefd entry is updated, else returns error assuming kernel program is not loaded.
	// It also verifies the next program pinned map is created or not.
	Start(ifaceName, direction string, chain bool) error

	// UpdateBPFMaps updates config ebpf maps via map arguments
	UpdateBPFMaps(ifacename, direction string) error

	// UpdateArgs updates the config map_args
	UpdateArgs(ifaceName, direction string) error

	// VerifyAndGetArtifacts checks if binary already exists and downloads artifacts from the specified eBPF repo
	VerifyAndGetArtifacts(conf *config.Config) error

	// IsRunning checks the status of the user program and returns if it is running or not
	IsRunning() (bool, error)

	// GetBPFMap returns a BPFMap given the map name of the BPFProgram
	GetBPFMap(mapName string) (BPFMap, error)

	// MonitorMaps fetches values from bpf maps and publishes to metrics
	MonitorMaps(ifaceName string, intervals int) error

	// PutNextProgFDFromID updates next program FD from program ID
	PutNextProgFDFromID(progID int) error

	// RemoveNextProgFD deletes the entry if it is the last program in the chain.
	// This method is called when sequence of the program changed to last in the chain
	RemoveNextProgFD() error

	// RemovePrevProgFD deletes the entry if the last element
	RemovePrevProgFD() error
}

// BPFMap
type BPFMap interface {
	// GetName returns the BPFMap name
	GetName() string

	// GetMapID returns the BPFMap ID
	GetMapID() ebpf.MapID

	// GetType returns the type of BPFMap
	GetType() ebpf.MapType

	// GetBPFProg returns the underlying BPF program
	GetBPFProg() BPF

	// UpdateMapID updates the BPFMap ID to the passed value
	UpdateMapID(mapID ebpf.MapID)

	// The update function is used to update eBPF maps, which are used by network functions.
	// Supported types are Array and Hash
	// Multiple values are comma separated
	// Hashmap can be multiple values or single values.
	// If hash map entries then key will be values and value will be set to 1
	// In case of Array then key will be index starting from 0 and values are stored.
	// for example:
	//
	//	HashMap scenario 1. --ports="80,443" values are stored in rl_ports_map BPF map
	//		key => 80 value => 1
	//		key => 443 value => 1
	//	HashMap scenario 2. --ports="443" value is stored in rl_ports_map BPF map
	//		key => 443 value => 1
	//	Array scenario 1. --ports="80,443" values are stored in rl_ports_map BPF map
	//		key => 0 value => 80
	//		key => 1 value => 443
	//	Array scenario 2. --rate="10000" value is stored in rl_config_map BPF map
	//		key => 0 value => 10000
	Update(value string) error
}
