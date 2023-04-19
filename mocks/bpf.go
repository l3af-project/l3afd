// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/models"
)

// BPF is a mock models.BPF for testing
type BPF struct {
	MockName                    func() string
	MockArtifact                func() string
	MockMapName                 func() string
	MockMapNamePth              func() string
	MockPrevMapNamePth          func() string
	MockProgId                  func() int
	MockSeqId                   func() int
	MockUpdatePrevMapNamePath   func(value string)
	MockUpdateAdminStatus       func(value string)
	MockStart                   func(ifaceName, direction string, chain bool) error
	MockStop                    func(ifaceName, direction string, chain bool) error
	MockUpdate                  func(ifaceName, direction string) error
	MockVerifyAndGetArtifacts   func(conf *config.Config) error
	MockGetArtifacts            func(conf *config.Config) error
	MockAddBPFMap               func(mapName string) error
	MockGetBPFMap               func(mapName string) (models.BPFMap, error)
	MockAddMetricsBPFMap        func(mapName, aggregator string, key, samplesLength int) error
	MockMonitorMaps             func(ifaceName string, intervals int) error
	MockPutNextProgFDFromID     func(progsID int) error
	MockGetProgID               func() (int, error)
	MockRemoveNextProgFD        func() error
	MockRemovePrevProgFD        func() error
	MockVerifyPinnedMapExists   func(chain bool) error
	MockVerifyPinnedMapVanish   func(chain bool) error
	MockVerifyProcessObject     func() error
	MockVerifyMetricsMapsVanish func() error
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

// MapNamePth implements model.BPF.MapNamePth
func (b *BPF) MapNamePth() string {
	return b.MockMapNamePth()
}

// PrevMapNamePth implements model.BPF.PrevMapNamePth
func (b *BPF) PrevMapNamePth() string {
	return b.MockPrevMapNamePth()
}

// ProgId implements models.BPF.ProgId
func (b *BPF) ProgId() int {
	return b.MockProgId()
}

// SeqId implements models.BPF.SeqId
func (b *BPF) SeqId() int {
	return b.MockSeqId()
}

// UpdatePrevMapNamePath implements models.BPF.UpdatePrevMapNamePath
func (b *BPF) UpdatePrevMapNamePath(value string) {
	b.MockUpdatePrevMapNamePath(value)
}

// UpdateAdminStatus implements models.BPF.ChangeAdminStatus
func (b *BPF) UpdateAdminStatus(value string) {
	b.MockUpdateAdminStatus(value)
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

// GetArtifacts implements models.BPF.GetArtifacts
func (b *BPF) GetArtifacts(conf *config.Config) error {
	return b.MockGetArtifacts(conf)
}

// AddBPFMap implements models.BPF.AddBPFMap
func (b *BPF) AddBPFMap(mapName string) error {
	return b.MockAddBPFMap(mapName)
}

// GetBPFMap implements models.BPF.GetBPFMap
func (b *BPF) GetBPFMap(mapName string) (models.BPFMap, error) {
	return b.MockGetBPFMap(mapName)
}

// AddMetricsBPFMap implements models.BPF.AddMetricsBPFMap
func (b *BPF) AddMetricsBPFMap(mapName, aggregator string, key, samplesLength int) error {
	return b.MockAddMetricsBPFMap(mapName, aggregator, key, samplesLength)
}

// MontitorMaps implements models.BPF.MonitorMaps
func (b *BPF) MonitorMaps(ifaceName string, intervals int) error {
	return b.MockMonitorMaps(ifaceName, intervals)
}

// PutNextProgFDFromID implements models.BPF.PutNextProgFDFromID
func (b *BPF) PutNextProgFDFromID(progsID int) error {
	return b.MockPutNextProgFDFromID(progsID)
}

// GetProgID implements models.BPF.GetProgID
func (b *BPF) GetProgID() (int, error) {
	return b.MockGetProgID()
}

// RemoveNextProgFD implements models.BPF.RemoveNextProgFD
func (b *BPF) RemoveNextProgFD() error {
	return b.MockRemoveNextProgFD()
}

// RemovePrevProgID implements models.BPF.RemovePrevProgFD
func (b *BPF) RemovePrevProgFD() error {
	return b.MockRemovePrevProgFD()
}

// VerifyPinnedMapExists implements models.BPF.VerifyPinnedMapExists
func (b *BPF) VerifyPinnedMapExists(chain bool) error {
	return b.MockVerifyPinnedMapExists(chain)
}

// VerifyPinnedMapVanish implements models.BPF.VerifyPinnedMapVanish
func (b *BPF) VerifyPinnedMapVanish(chain bool) error {
	return b.MockVerifyPinnedMapVanish(chain)
}

// VerifyProcessObject implements models.BPF.VerifyProcessObject
func (b *BPF) VerifyProcessObject() error {
	return b.MockVerifyProcessObject()
}

// VerifyMetricsMapVanish implements models.BPF.VerifyMetricsMapVanish
func (b *BPF) VerifyMetricsMapsVanish() error {
	return b.MockVerifyMetricsMapsVanish()
}

type BPFMap struct {
	MockUpdate func(value string) error
}

var _ models.BPFMap = &BPFMap{}

// Update implements models.BPFMap.Update
func (b *BPFMap) Update(value string) error {
	return b.MockUpdate(value)
}
