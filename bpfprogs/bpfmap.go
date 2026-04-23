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
	"github.com/l3af-project/l3afd/v2/decode"
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
	Key        decode.FieldSchema
	Values     *ring.Ring
	Aggregator string
	LastValue  float64
}

// TODO TO COMPLEE REMOVEMISSINGKEYS IMPLEMENTATION
// The RemoveMissingKeys function is used to delete missing entries of eBPF maps, which are used by eBPF Programs.
func (b *BPFMap) RemoveMissingKeys(args []models.KeyValueInternal) error {
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		return fmt.Errorf("access new map from ID failed %w", err)
	}
	defer ebpfMap.Close()
	KeyValueMap := make(map[decode.Field]bool, len(args))
	for _, k := range args {
		KeyValueMap[k.Key] = true
	}
	var key, nextKey decode.Field
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
func (b *BPFMap) Update(key, value decode.Field) error {
	log.Debug().Msgf("update map name %s ID %d", b.Name, b.MapID)
	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		return fmt.Errorf("access new map from ID failed %w", err)
	}
	defer ebpfMap.Close()
	kb, err := key.Serialize()
	if err != nil {
		return fmt.Errorf("serialize key: %w", err)
	}
	vb, err := value.Serialize()
	if err != nil {
		return fmt.Errorf("serialize value: %w", err)
	}
	log.Info().Msgf("updating map %s key %d mapid %d", b.Name, key, b.MapID)
	if err := ebpfMap.Put(kb, vb); err != nil {
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
			fmt.Println(err)
			log.Warn().Err(err).Msgf("GetValue: Update new map ID %d", tmpBPF.MapID)
			return 0
		}
		log.Info().Msgf("GetValue: Update new map ID %d", tmpBPF.MapID)
		b.MapID = tmpBPF.MapID
		ebpfMap, err = ebpf.NewMapFromID(b.MapID)
		if err != nil {
			fmt.Println(err)
			log.Warn().Err(err).Msgf("GetValue : retry of NewMapFromID failed ID %d", b.MapID)
			return 0
		}
	}
	defer ebpfMap.Close()
	parsedKey, err := decode.ParseSchema(b.Key)
	if err != nil {
		fmt.Println(err)
		log.Warn().Err(err).Msgf("GetValue ParseSchema failed : Name %s ID %d", b.Name, b.MapID)
		return 0
	}
	// fmt.Printf(" ATUL. %v", parsedKey)
	kb, err := parsedKey.Serialize()
	if err != nil {
		fmt.Println("ATUL1")
		fmt.Println(err)
		return 0
	}
	// info, err := ebpfMap.Info()
	// if err != nil {
	// 	// handle error
	// 	fmt.Println(err)
	// 	return 0
	// }
	// fmt.Printf(" keysize %d value size %d\n", info.KeySize, info.ValueSize)
	var fvalue decode.Uint64Field
	vb := make([]byte, fvalue.Size())
	// fmt.Printf(" keysize %d value size %d\n", parsedKey.Size(), fvalue.Size())
	if err := ebpfMap.Lookup(kb, &vb); err != nil {
		fmt.Println("ATUL2")
		fmt.Println(err)
		return 0
	}
	_, err = fvalue.Deserialize(vb, 0)
	if err != nil {
		fmt.Println("ATUL3")
		fmt.Println(err)
		return 0
	}
	value := fvalue.Value
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
