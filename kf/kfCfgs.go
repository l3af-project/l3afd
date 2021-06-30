package kf

import (
	"fmt"
	"path/filepath"
	"sync"

	"tbd/cfgdist/cdbs"

	"tbd/cfgdist/kvstores"
	"tbd/go-shared/logs"

	"tbd/admind/models"
	"tbd/cfgdist/kvstores/emitter"
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
	logs.IfErrorLogf(err, "error handling event for key %s", key)
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
		logs.Errorf("value not found for the key %s", keySting)
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

	logs.Infof("KF config command  : %s %v", cmdPath, args)
	cmd := execCommand(cmdPath, args...)

	c.MutexLock.Lock()
	defer c.MutexLock.Unlock()

	if err := cmd.Start(); err != nil {
		logs.Infof("user mode KF config command failed - %s %v", c.Program.Name, err)
		return fmt.Errorf("failed to start : %s %v", cmd, args)
	}

	return nil
}
