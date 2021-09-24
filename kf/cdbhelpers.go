// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
// +build configs
//

// Package kf provides primitives for CDB helpers.
package kf

import (
	"context"
	"fmt"
	"os"
	"time"

	"walmart-internal/cfgdist/cdbs"
	"walmart-internal/cfgdist/kvstores"
	"walmart-internal/cfgdist/kvstores/cdbkv"
	"walmart-internal/cfgdist/kvstores/emitter"
	"walmart-internal/cfgdist/kvstores/versionannouncer"
	"walmart-internal/go-shared/nsqbatch"
	"walmart-internal/l3afd/config"
	"walmart-internal/l3afd/pidfile"

	"github.com/rs/zerolog/log"
)

var cdbFile = "/var/tb/cdb/l3afd.cdb"

func StartConfigWatcher(ctx context.Context, hostName, daemonName string, conf *config.Config, nfConfigs *NFConfigs) error {
	var producer nsqbatch.Producer
	var err error
	if prefs := nsqbatch.GetSystemPrefs(); prefs.Enabled {
		producer, err = nsqbatch.NewProducer(prefs)
		if err != nil {
			log.Error().Err(err).Msg("could not set up nsqd")
			return fmt.Errorf("could not set up nsqd: %v", err)
		}
	}
	netNamespace := os.Getenv("TBNETNAMESPACE")
	verifyCDB := false
	invalidIsFatal := false
	cdbStore, err := KVStoreFromCDB(cdbFile, "", verifyCDB, invalidIsFatal)
	if err != nil {
		return fmt.Errorf("Failed to get kv store from cdb: %w", err)
	}

	cdbKVStore, err := versionannouncer.NewVersionAnnouncer(ctx, hostName, daemonName,
		netNamespace, cdbFile, conf.DataCenter, cdbStore, producer)
	if err != nil {
		log.Fatal().Err(err).Msg("cdb error")
	}

	emit := emitter.NewKVStoreChangeEmitter(cdbKVStore)

	if err := emit.RegisterHandler(nfConfigs); err != nil {
		return fmt.Errorf("failed to register nfconfigs: %w", err)
	}

	pidfile.SetupGracefulShutdown(func() error {
		if len(nfConfigs.IngressXDPBpfs) > 0 || len(nfConfigs.IngressTCBpfs) > 0 || len(nfConfigs.EgressTCBpfs) > 0 {
			ctx, cancelfunc := context.WithTimeout(context.Background(), conf.ShutdownTimeout*time.Second)
			defer cancelfunc()
			if err := nfConfigs.Close(ctx); err != nil {
				log.Error().Err(err).Msg("stopping all network functions failed")
			}
		}
		if err := emit.Close(); err != nil {
			log.Error().Err(err).Msg("kv store emit close failed")
		}
		return nil
	}, conf.ShutdownTimeout, conf.PIDFilename)

	return nil
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

func (c *NFConfigs) HandleError(err error, et kvstores.EventType, key, val []byte) {
	if err != nil {
		log.Error().Err(err).Msgf("error handling event for key %s")
	}
}

func (c *NFConfigs) HandleAdded(key, val []byte) error {
	return c.HandleUpdated(key, val)
}
