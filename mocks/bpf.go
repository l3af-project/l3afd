// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"github.com/cilium/ebpf"
	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/models"
)

// BPF is a mock models.BPF for testing
type BPF struct {
	MockName                  func() string
	MockArtifact              func() string
	MockMapName               func() string
	MockProgId                func() int
	MockSeqId                 func() int
	MockAdminStatus           func() string
	MockVersion               func() string
	MockGetRestartCount       func() int
	MockGetProgram            func() *models.BPFProgram
	MockGetMapNamePath        func() string
	MockGetPrevMapNamePath    func() string
	MockAddToRestartCount     func(value int)
	MockUpdateAdminStatus     func(value string)
	MockUpdateProgram         func(value *models.BPFProgram)
	MockUpdatePrevMapNamePath func(value string)
	MockStop                  func(ifaceName, direction string, chain bool) error
	MockStart                 func(ifaceName, direction string, chain bool) error
	MockUpdate                func(ifaceName, direction string) error
	MockVerifyAndGetArtifacts func(conf *config.Config) error
	MockIsRunning             func() (bool, error)
	MockGetBPFMap             func(mapName string) (models.BPFMap, error)
	MockMonitorMaps           func(ifaceName string, intervals int) error
	MockPutNextProgFDFromID   func(progsID int) error
	MockRemoveNextProgFD      func() error
	MockRemovePrevProgFD      func() error
}

var _ models.BPF = &BPF{}

// Name implements models.BPF.Name
func (b *BPF) Name() string {
	return b.MockName()
}

// Artifact implements models.BPF.Artifact
func (b *BPF) Artifact() string {
	return b.MockArtifact()
}

// MapName implements model.BPF.MapName
func (b *BPF) MapName() string {
	return b.MockMapName()
}

// ProgId implements models.BPF.ProgId
func (b *BPF) ProgId() int {
	return b.MockProgId()
}

// SeqId implements models.BPF.SeqId
func (b *BPF) SeqId() int {
	return b.MockSeqId()
}

// AdminStatus implements models.BPF.AdminStatus
func (b *BPF) AdminStatus() string {
	return b.MockAdminStatus()
}

// Version implements models.BPF.Version
func (b *BPF) Version() string {
	return b.MockVersion()
}

// GetRestartCount implements models.BPF.GetRestartCount
func (b *BPF) GetRestartCount() int {
	return b.MockGetRestartCount()
}

// GetProgram implements models.BPF.GetProgram
func (b *BPF) GetProgram() *models.BPFProgram {
	return b.MockGetProgram()
}

// MapNamePth implements model.BPF.GetMapNamePath
func (b *BPF) GetMapNamePath() string {
	return b.MockGetMapNamePath()
}

// PrevMapNamePth implements model.BPF.GetPrevMapNamePath
func (b *BPF) GetPrevMapNamePath() string {
	return b.MockGetPrevMapNamePath()
}

// AddToRestartCount implements models.BPF.AddToRestartCount
func (b *BPF) AddToRestartCount(value int) {
	b.MockAddToRestartCount(value)
}

// UpdateAdminStatus implements models.BPF.ChangeAdminStatus
func (b *BPF) UpdateAdminStatus(value string) {
	b.MockUpdateAdminStatus(value)
}

// UpdateProgram implements models.BPF.UpdateProgram
func (b *BPF) UpdateProgram(value *models.BPFProgram) {
	b.MockUpdateProgram(value)
}

// UpdatePrevMapNamePath implements models.BPF.UpdatePrevMapNamePath
func (b *BPF) UpdatePrevMapNamePath(value string) {
	b.MockUpdatePrevMapNamePath(value)
}

// Start implements models.BPF.Start
func (b *BPF) Start(ifaceName, direction string, chain bool) error {
	return b.MockStart(ifaceName, direction, chain)
}

// Stop implements models.BPF.Stop
func (b *BPF) Stop(ifaceName, direction string, chain bool) error {
	return b.MockStop(ifaceName, direction, chain)
}

// Update implements models.BPF.Stop
func (b *BPF) Update(ifaceName, direction string) error {
	return b.MockUpdate(ifaceName, direction)
}

// VerifyAndGetArtifacts implements models.BPF.VerifyAndGetArtifact
func (b *BPF) VerifyAndGetArtifacts(conf *config.Config) error {
	return b.MockVerifyAndGetArtifacts(conf)
}

// IsRunning implements models.BPF.IsRunning
func (b *BPF) IsRunning() (bool, error) {
	return b.MockIsRunning()
}

// GetBPFMap implements models.BPF.GetBPFMap
func (b *BPF) GetBPFMap(mapName string) (models.BPFMap, error) {
	return b.MockGetBPFMap(mapName)
}

// MontitorMaps implements models.BPF.MonitorMaps
func (b *BPF) MonitorMaps(ifaceName string, intervals int) error {
	return b.MockMonitorMaps(ifaceName, intervals)
}

// PutNextProgFDFromID implements models.BPF.PutNextProgFDFromID
func (b *BPF) PutNextProgFDFromID(progsID int) error {
	return b.MockPutNextProgFDFromID(progsID)
}

// RemoveNextProgFD implements models.BPF.RemoveNextProgFD
func (b *BPF) RemoveNextProgFD() error {
	return b.MockRemoveNextProgFD()
}

// RemovePrevProgID implements models.BPF.RemovePrevProgFD
func (b *BPF) RemovePrevProgFD() error {
	return b.MockRemovePrevProgFD()
}

type BPFMap struct {
	MockGetName     func() string
	MockGetMapID    func() ebpf.MapID
	MockGetType     func() ebpf.MapType
	MockGetBPFProg  func() models.BPF
	MockUpdateMapID func(mapID ebpf.MapID)
	MockUpdate      func(value string) error
}

var _ models.BPFMap = &BPFMap{}

// GetName implements models.BPFMap.GetName
func (b *BPFMap) GetName() string {
	return b.MockGetName()
}

// GetMapID implements models.BPFMap.GetMapID
func (b *BPFMap) GetMapID() ebpf.MapID {
	return b.MockGetMapID()
}

// GetType implements models.BPFMap.GetType
func (b *BPFMap) GetType() ebpf.MapType {
	return b.MockGetType()
}

// GetBPFProg implements models.BPF.GetBPFProg
func (b *BPFMap) GetBPFProg() models.BPF {
	return b.MockGetBPFProg()
}

// UpdateMapID implements models.BPFMap.UpdateMapID
func (b *BPFMap) UpdateMapID(mapID ebpf.MapID) {
	b.MockUpdateMapID(mapID)
}

// Update implements models.BPFMap.Update
func (b *BPFMap) Update(value string) error {
	return b.MockUpdate(value)
}
