package kf

import (
	"fmt"
	"strings"
	"unsafe"
	"strconv"
	"tbd/Torbit/go-shared/logs"
	"github.com/cilium/ebpf"
)
type BPFMap struct {
	Name string
	MapID ebpf.MapID
	Type ebpf.MapType
}

// This function is used to update eBPF maps, which are used by network functions.
// Supported types are Array and HashMap
// multiple values are comma separated
// Hashmap can be multiple values or single values.
// if map has single entry then key will be 0 and value will be updated.
// if map has multiple entry then key will be value and value will be 1
// In case of Array then key will be index and value are stored.

func (b *BPFMap)Update(value string) error {

	logs.Debugf("update map name %s ID %d", b.Name, b.MapID)
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
				logs.Warningf("delete hash map for key %d failed %v", key, err)
			}
		}

		if len(s) < 2 {
			v, _ := strconv.ParseInt(s[0], 10, 64)
			k := 0
			if err := ebpfMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0); err != nil {
				return fmt.Errorf("update hash map for key 0 failed %v", err)
			}
			return nil
		}

		for key, val := range s {
			v, _ := strconv.ParseInt(val, 10, 64)
			x := 1
			logs.Debugf("updating map %s key %d mapid %d", b.Name,v,b.MapID)
			if err := ebpfMap.Update(unsafe.Pointer(&v), unsafe.Pointer(&x), 0); err != nil {
				return fmt.Errorf("update hash map element failed for key %d error %v", key, err)
			}
		}
	} else if b.Type == ebpf.Array {
		for key, val := range s {
			v, _ := strconv.ParseInt(val, 10, 64)
			if err := ebpfMap.Update(unsafe.Pointer(&key), &v, 0); err != nil {
				return fmt.Errorf("update array map index %d %v\n", key, err)
			}
		}
	} else {
		return fmt.Errorf("unsupported map type")
	}
	return nil
}

// Get value of the map for key 0
func (b *BPFMap) GetValue() int64 {

	ebpfMap, err := ebpf.NewMapFromID(b.MapID)
	if err != nil {
		logs.Warningf("GetValue : NewMapFromID failed ID %d  err %v",b.MapID, err)
		return 0
	}
	defer ebpfMap.Close()

	var value int64
	key := 0

	if err = ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		logs.Warningf("GetValue Lookup failed : %v", err)
		return 0
	}

	return value
}
