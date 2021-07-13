// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for CDB helpers.
package kf

import (
	"context"
	"fmt"

	"tbd/cfgdist/cdbs"
	"tbd/cfgdist/kvstores"
	"tbd/cfgdist/kvstores/cdbkv"
	"tbd/cfgdist/kvstores/versionannouncer"
	"tbd/go-shared/nsqbatch"
)

func VersionAnnouncerFromCDB(ctx context.Context, hostName, daemonName, netNamespace,
	cdbFile, clusterName, presharedSecretPath string, verifyCDB, invalidIsFatal bool,
	producer nsqbatch.Producer) (kvstores.IterableWatchableKVStore, error) {
	cdbStore, err := KVStoreFromCDB(cdbFile, presharedSecretPath, verifyCDB, invalidIsFatal)
	if err != nil {
		return nil, fmt.Errorf("Failed to get kv store from cdb: %w", err)
	}

	return versionannouncer.NewVersionAnnouncer(ctx, hostName, daemonName,
		netNamespace, cdbFile, clusterName, cdbStore, producer)
}

func KVStoreFromCDB(cdbFile, presharedSecretPath string, verifyCDB,
	invalidIsFatal bool) (kvstores.IterableWatchableKVStore, error) {
	hotCdb, err := cdbs.LoadHotCDB(cdbFile, presharedSecretPath, verifyCDB, invalidIsFatal)
	if err != nil {
		return nil, fmt.Errorf("Load host cdb failed: %w", err)
	}
	return cdbkv.NewWatchableCDBKVStore(hotCdb, NewL3afDeleteGuardFact), nil
}

func NewL3afDeleteGuardFact() cdbkv.DeleteGuard {
	return new(l3afDeleteGuard)
}

type l3afDeleteGuard struct {
	ok bool
}

func (l *l3afDeleteGuard) ProcessKey(key, val []byte) {
	if !l.ok && l.goodKey(key) && l.goodVal(val) {
		l.ok = true
	}
}

func (l *l3afDeleteGuard) CanDelete() bool {
	return l.ok
}

func (l *l3afDeleteGuard) goodKey(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	strKey := string(key)
	if strKey == cdbs.GetGenTimeKey() {
		return false
	}
	//if strKey == cdbs.GetSignatureKey() {
	//	return false
	//}
	return true
}

func (l *l3afDeleteGuard) goodVal(val []byte) bool {
	//sr := io.NewSectionReader(bytes.NewReader(val), 0, int64(len(val)))
	//_, err := originconfig.Load(sr, "datacenter")
	//return err == nil
	//TODO Need to be implemented

	return true
}
