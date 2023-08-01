// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package models

import "github.com/l3af-project/l3afd/config"

// BPF
type BPF interface {
	//
	Name() string

	//
	Artifact() string

	//
	MapName() string

	//
	MapNamePth() string

	//
	PrevMapNamePth() string

	//
	ProgId() int

	//
	SeqId() int

	//
	UpdateAdminStatus(value string)

	//
	UpdatePrevMapNamePath(value string)

	//
	Start(ifaceName, direction string, chain bool) error

	//
	Stop(ifaceName, direction string, chain bool) error

	//
	Update(ifaceName, direction string) error

	//
	VerifyAndGetArtifacts(conf *config.Config) error

	//
	GetArtifacts(conf *config.Config) error

	//
	AddBPFMap(mapName string) error

	//
	GetBPFMap(mapName string) (BPFMap, error)

	//
	AddMetricsBPFMap(mapName, aggregator string, key, samplesLength int) error

	//
	MonitorMaps(ifaceName string, intervals int) error

	//
	PutNextProgFDFromID(progsID int) error

	//
	GetProgID() (int, error)

	//
	RemoveNextProgFD() error

	//
	RemovePrevProgFD() error

	//
	VerifyPinnedMapExists(chain bool) error

	//
	VerifyPinnedMapVanish(chain bool) error

	//
	VerifyProcessObject() error

	//
	VerifyMetricsMapsVanish() error
}

// BPFMap
type BPFMap interface {
	//
	Update(value string) error
}
