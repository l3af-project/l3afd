// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"container/ring"
	"errors"
	"fmt"
	"math"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/rs/zerolog/log"
)

type BPFMap struct {
	Name  string
	MapID ebpf.MapID
	Type  ebpf.MapType

	// BPFProg reference in case of stale map id
	BPFProg *BPF `json:"-"`
}

// This stores Metrics map details.
type MetricsBPFMap struct {
	BPFMap
	Key        int
	Values     *ring.Ring
	Aggregator string
	LastValue  float64
}

// The RemoveMissingKeys function is used to delete missing entries of eBPF maps, which are used by eBPF Programs.
func (b *BPFMap) RemoveMissingKeys(args []models.KeyValue) error {
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		return fmt.Errorf("access new map from ID failed %w", err)
	}
	defer ebpfMap.Close()
	KeyValueMap := make(map[int]bool, len(args))
	for _, k := range args {
		KeyValueMap[k.Key] = true
	}
	var key, nextKey int
	for {
		err := ebpfMap.NextKey(unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			} else {
				return fmt.Errorf("get next key failed with error %w, mapid %d", err, b.MapID)
			}
		}
		key = nextKey
		_, IsKeyExists := KeyValueMap[key]
		if !IsKeyExists {
			log.Info().Msgf("removing key %v because it is missing\n", key)
			if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
				return fmt.Errorf("delete key failed with error %w, mapid %d", err, b.MapID)
			}
		}
	}
	return nil
}

// The update function is used to update eBPF maps, which are used by eBPF programs.
func (b *BPFMap) Update(key, value int) error {

	log.Debug().Msgf("update map name %s ID %d", b.Name, b.MapID)
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		return fmt.Errorf("access new map from ID failed %w", err)
	}
	defer ebpfMap.Close()
	log.Info().Msgf("updating map %s key %d mapid %d", b.Name, key, b.MapID)
	if err := ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), 0); err != nil {
		return fmt.Errorf("update hash map element failed for key %d error %w", key, err)
	}
	return nil
}

// Get value of the map for given key
// There are 2 aggregators are supported here
// max-rate - this calculates delta requests / sec and stores absolute value.
// avg - stores the values in the circular queue
// We can implement more aggregate function as needed.
func (b *MetricsBPFMap) GetValue() float64 {
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		// We have observed in smaller configuration VM's, if we restart BPF's
		// Stale mapID's are reported, in such cases re-checking map id
		log.Warn().Err(err).Msgf("GetValue : NewMapFromID failed ID %d, re-looking up of map id", b.MapID)
		tmpBPF, err := b.BPFProg.GetBPFMap(b.Name)
		if err != nil {
			log.Warn().Err(err).Msgf("GetValue: Update new map ID %d", tmpBPF.MapID)
			return 0
		}
		log.Info().Msgf("GetValue: Update new map ID %d", tmpBPF.MapID)
		b.MapID = tmpBPF.MapID
		ebpfMap, err = ebpf.NewMapFromID(b.MapID)
		if err != nil {
			log.Warn().Err(err).Msgf("GetValue : retry of NewMapFromID failed ID %d", b.MapID)
			return 0
		}
	}
	defer ebpfMap.Close()

	var value int64
	if err = ebpfMap.Lookup(unsafe.Pointer(&b.Key), unsafe.Pointer(&value)); err != nil {
		log.Warn().Err(err).Msgf("GetValue Lookup failed : Name %s ID %d", b.Name, b.MapID)
		return 0
	}

	var retVal float64
	switch b.Aggregator {
	case "scalar":
		retVal = float64(value)
	case "max-rate":
		b.Values = b.Values.Next()
		b.Values.Value = math.Abs(float64(float64(value) - b.LastValue))
		b.LastValue = float64(value)
		retVal = b.MaxValue()
	case "avg":
		b.Values.Value = value
		b.Values = b.Values.Next()
		retVal = b.AvgValue()
	default:
		log.Warn().Msgf("unsupported aggregator %s and value %d", b.Aggregator, value)
	}
	return retVal
}

// This method  finds the max value in the circular list
func (b *MetricsBPFMap) MaxValue() float64 {
	tmp := b.Values
	var max float64
	for i := 0; i < b.Values.Len(); i++ {
		if tmp.Value != nil {
			val := tmp.Value.(float64)
			if max < val {
				max = val
			}
		}
		tmp = tmp.Next()
	}
	return max
}

// This method calculates the average
func (b *MetricsBPFMap) AvgValue() float64 {
	tmp := b.Values.Next()
	var sum float64
	var n float64 = 0.0
	for i := 0; i < b.Values.Len(); i++ {
		if tmp.Value != nil {
			sum = sum + tmp.Value.(float64)
			n = n + 1
		}
		tmp = tmp.Next()
	}
	return sum / n
}
