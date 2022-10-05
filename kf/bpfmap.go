// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"container/ring"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
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
	key        int
	Values     *ring.Ring
	aggregator string
	lastValue  float64
}

// The update function is used to update eBPF maps, which are used by network functions.
// Supported types are Array and Hash
// Multiple values are comma separated
// Hashmap can be multiple values or single values.
// If hash map entries then key will be values and value will be set to 1
// In case of Array then key will be index starting from 0 and values are stored.
// for e.g.
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
func (b *BPFMap) Update(value string) error {

	log.Debug().Msgf("update map name %s ID %d", b.Name, b.MapID)
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		return fmt.Errorf("access new map from ID failed %v", err)
	}
	defer ebpfMap.Close()

	// check values are single or multiple
	s := strings.Split(value, ",")

	if b.Type == ebpf.Hash {
		// clear map elements
		key := 0
		val := 0
		entries := ebpfMap.Iterate()
		for entries.Next(unsafe.Pointer(&key), unsafe.Pointer(&val)) {
			// Order of keys is non-deterministic due to randomized map seed
			if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
				log.Warn().Err(err).Msgf("delete hash map for key %d failed", key)
			}
		}

		for key, val := range s {
			v, _ := strconv.ParseInt(val, 10, 64)
			x := 1
			log.Info().Msgf("updating map %s key %d mapid %d", b.Name, v, b.MapID)
			if err := ebpfMap.Update(unsafe.Pointer(&v), unsafe.Pointer(&x), 0); err != nil {
				return fmt.Errorf("update hash map element failed for key %d error %v", key, err)
			}
		}
	} else if b.Type == ebpf.Array {
		for key, val := range s {
			v, _ := strconv.ParseInt(val, 10, 64)
			log.Info().Msgf("updating map %s key %d mapid %d", b.Name, v, b.MapID)
			if err := ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&v), 0); err != nil {
				return fmt.Errorf("update array map index %d %v", key, err)
			}
		}
	} else {
		return fmt.Errorf("unsupported map type")
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
		// We have observed in smaller configuration VM's, if we restart KF's
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
	if err = ebpfMap.Lookup(unsafe.Pointer(&b.key), unsafe.Pointer(&value)); err != nil {
		log.Warn().Err(err).Msgf("GetValue Lookup failed : Name %s ID %d", b.Name, b.MapID)
		return 0
	}

	var retVal float64
	switch b.aggregator {
	case "scalar":
		retVal = float64(value)
	case "max-rate":
		b.Values = b.Values.Next()
		b.Values.Value = math.Abs(float64(float64(value) - b.lastValue))
		b.lastValue = float64(value)
		retVal = b.MaxValue()
	case "avg":
		b.Values.Value = value
		b.Values = b.Values.Next()
		retVal = b.AvgValue()
	default:
		log.Warn().Msgf("unsupported aggregator %s and value %d", b.aggregator, value)
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
