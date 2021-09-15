// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
// +build configs
//

package kf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"tbd/Torbit/cfgdist/cdbs"
	"tbd/Torbit/cfgdist/kvstores"
	"tbd/Torbit/cfgdist/kvstores/emitter"
	"tbd/Torbit/cfgdist/kvstores/versionannouncer"
	"tbd/Torbit/go-shared/nsqbatch"
	"tbd/Torbit/l3afd/models"

	"github.com/rs/zerolog/log"
)

type KFCfgs struct {
	cfgs      sync.Map
	Program   *models.BPFProgram
	FilePath  string
	MutexLock *sync.Mutex
}

func NewKFCfgs(emit emitter.KeyChangeEmitter, filePath string, program *models.BPFProgram) (*KFCfgs, error) {
	kfCfgs := &KFCfgs{
		Program:   program,
		FilePath:  filePath,
		MutexLock: new(sync.Mutex),
	}

	if err := emit.RegisterHandler(kfCfgs); err != nil {
		return nil, fmt.Errorf("failed to register KFCfgs: %w", err)
	}

	return kfCfgs, nil
}

func (c *KFCfgs) HandleError(err error, et kvstores.EventType, key, val []byte) {
	if err != nil {
		log.Error().Err(err).Msgf("error handling event for key %s", key)
	}
}

func (c *KFCfgs) HandleDeleted(key []byte) error {

	keySting := string(key)

	args := make([]string, 0, len(c.Program.ConfigArgs)<<1)
	args = append(args, "--action=del")
	args = append(args, "--key="+keySting)

	val, ok := c.cfgs.Load(keySting)
	if ok {
		args = append(args, "--val="+val.(string))
	} else {
		log.Error().Msgf("value not found for the key %s", keySting)
	}

	c.RunCommand(args)
	c.cfgs.Delete(keySting)
	return nil
}

// HandleAdded Do Actions required on any key add/update
func (c *KFCfgs) HandleAdded(key, val []byte) error {
	keySting := string(key)

	// Skip the record if it's a key we don't care about
	if keySting == cdbs.GetGenTimeKey() || keySting == cdbs.GetSignatureKey() || keySting == cdbs.CdbMetaKey {
		return nil
	}

	// command config
	args := make([]string, 0, len(c.Program.ConfigArgs)<<1)
	args = append(args, "--action=added")
	args = append(args, "--key="+keySting)
	args = append(args, "--val="+string(val))

	c.RunCommand(args)
	c.cfgs.Store(keySting, string(val))
	return nil
}

// HandleUpdated Do Actions required on any key add/update
func (c *KFCfgs) HandleUpdated(key, val []byte) error {

	keySting := string(key)

	// Skip the record if it's a key we don't care about
	if keySting == cdbs.GetGenTimeKey() || keySting == cdbs.GetSignatureKey() || keySting == cdbs.CdbMetaKey {
		return nil
	}

	// command config
	args := make([]string, 0, len(c.Program.ConfigArgs)<<1)
	args = append(args, "--action=updated")
	args = append(args, "--key="+keySting)
	args = append(args, "--val="+string(val))

	c.RunCommand(args)
	c.cfgs.Store(keySting, string(val))
	return nil
}

func (c *KFCfgs) RunCommand(args []string) error {

	cmdPath := filepath.Join(c.FilePath, c.Program.CmdConfig)
	// Validate
	if err := assertExecutable(cmdPath); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %w", c.Program.CmdConfig, err)
	}

	for _, val := range c.Program.ConfigArgs {
		args = append(args, "--"+val.Key+"="+val.Value)
	}

	log.Info().Msgf("KF config command  : %s %v", cmdPath, args)
	cmd := execCommand(cmdPath, args...)

	c.MutexLock.Lock()
	defer c.MutexLock.Unlock()

	if err := cmd.Start(); err != nil {
		log.Info().Msgf("user mode KF config command failed - %s %v", c.Program.Name, err)
		return fmt.Errorf("failed to start : %s %v", cmd, args)
	}

	return nil
}

func (b *BPF) RunKFConfigs() error {

	netNamespace := os.Getenv("TBNETNAMESPACE")
	machineHostname, err := os.Hostname()
	if err != nil {
		log.Error().Err(err).Msg("Could not get hostname from OS")
	}

	daemonName := b.Program.Name

	var producer nsqbatch.Producer
	if prefs := nsqbatch.GetSystemPrefs(); prefs.Enabled {
		producer, err = nsqbatch.NewProducer(prefs)
		if err != nil {
			log.Error().Err(err).Msg("could not set up nsqd Details")
			return fmt.Errorf("could not set up nsqd: %v", err)
		}
	}

	verifyCDB := false
	invalidIsFatal := false
	cdbStore, err := KVStoreFromCDB(cdbFile, "", verifyCDB, invalidIsFatal)
	if err != nil {
		return fmt.Errorf("Failed to get kv store from cdb: %w", err)
	}
	cdbKVStore, err := versionannouncer.NewVersionAnnouncer(b.Ctx, machineHostname, daemonName,
		netNamespace, b.Program.ConfigFilePath, b.DataCenter, cdbStore, producer)

	if err != nil {
		return fmt.Errorf("error in KFConfig %s version announcer: %v", b.Program.Name, err)
	}
	emit := emitter.NewKVStoreChangeEmitter(cdbKVStore)

	_, err = NewKFCfgs(emit, b.FilePath, &b.Program)
	if err != nil {
		return fmt.Errorf("failed to start monitoring KF specific config %v", err)
	}

	select {
	case <-b.Done:
		log.Info().Msgf("KF config %s kv emitter close invoked", b.Program.Name)
		emit.Close()
		return nil
	}
	return nil
}
