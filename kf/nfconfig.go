// Package kf provides primitives for l3afd's network function configs.
package kf

import (
	"container/list"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"syscall"
	"sync"
	"time"

	"tbd/Torbit/admind/models"
	"tbd/Torbit/cfgdist/kvstores"
	"tbd/Torbit/cfgdist/kvstores/emitter"
	"tbd/Torbit/go-shared/logs"
	"tbd/Torbit/net/context"
	"tbd/Torbit/l3afd/config"
)

type NFConfigs struct {
	hostName string
	configs  sync.Map // key: string, val: *models.L3afDNFConfigDetail
	// These holds bpf programs in the list
	// map keys are network iface names index's are seq_id, position in the chain
	// root element will be root program
	IngressXDPBpfs map[string]*list.List
	IngressTCBpfs  map[string]*list.List
	EgressTCBpfs   map[string]*list.List

	hostConfig *config.Config
	processMon *pCheck
}

var shutdownInterval = 900 * time.Millisecond

func NewNFConfigs(emit emitter.KeyChangeEmitter, host string, hostConf *config.Config, pMon *pCheck) (*NFConfigs, error) {
	nfConfigs := &NFConfigs{
		hostName:       host,
		hostConfig:     hostConf,
		IngressXDPBpfs: make(map[string]*list.List),
		IngressTCBpfs:  make(map[string]*list.List),
		EgressTCBpfs:   make(map[string]*list.List),
	}

	if err := emit.RegisterHandler(nfConfigs); err != nil {
		return nil, fmt.Errorf("failed to register nfconfigs: %w", err)
	}
	nfConfigs.processMon = pMon
	nfConfigs.processMon.pCheckStart(nfConfigs.IngressXDPBpfs, nfConfigs.IngressTCBpfs, nfConfigs.EgressTCBpfs)
	return nfConfigs, nil
}

func (c *NFConfigs) HandleError(err error, et kvstores.EventType, key, val []byte) {
	logs.IfErrorLogf(err, "error handling event for key %s", key)
}

func (c *NFConfigs) HandleDeleted(key []byte) error {
	c.configs.Delete(string(key))
	return nil
}

func (c *NFConfigs) HandleAdded(key, val []byte) error {
	return c.HandleUpdated(key, val)
}

// HandleUpdated Do Actions required on any key add/update
func (c *NFConfigs) HandleUpdated(key, val []byte) error {
	if string(key) != c.hostName {
		return nil
	}

	cfg := make(map[string]map[string]map[string]map[string]models.BPFProgram)
	if err := json.Unmarshal(val, &cfg); err != nil {
		return fmt.Errorf("error decoding network function config: %w", err)
	}
	cfgbpfProgs, ok := cfg["bpf_programs"]
	if !ok {
		logs.Debugf("No BPF Programs in the config")
		return nil
	}
	// Reading from CDB
	for ifaceName, ifaceBPFProgs := range cfgbpfProgs { // iface name
		for direction, dirBpfProg := range ifaceBPFProgs { // direction ingress or egress
			for _, bpfProg := range dirBpfProg { // seq_id for chaining
				switch direction {
				case models.XDPIngressType:
					if c.IngressXDPBpfs[ifaceName] == nil {
						if bpfProg.AdminStatus == models.Enabled {
							c.IngressXDPBpfs[ifaceName] = list.New()
							if err := c.VerifyAndStartXDPRootProgram(ifaceName, direction); err != nil {
								return fmt.Errorf("failed to chain XDP BPF programs: %w", err)
							}
							logs.Infof("Push Back and Start XDP program : %s seq_id : %d", bpfProg.Name, bpfProg.SeqID)
							if err := c.PushBackAndStartBPF(&bpfProg, ifaceName, direction); err != nil {
								return fmt.Errorf("failed to update BPF Program: %w", err)
							}
						}
					} else if err := c.VerifyNUpdateBPFProgram(&bpfProg, ifaceName, direction); err != nil {
						return fmt.Errorf("failed to update xdp BPF Program: %w", err)
					}
				case models.IngressType:
					if c.IngressTCBpfs[ifaceName] == nil {
						if bpfProg.AdminStatus == models.Enabled {
							c.IngressTCBpfs[ifaceName] = list.New()
							if err := c.VerifyAndStartTCRootProgram(ifaceName, direction); err != nil {
								return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
							}
							if err := c.PushBackAndStartBPF(&bpfProg, ifaceName, direction); err != nil {
								return fmt.Errorf("failed to update BPF Program: %w", err)
							}
						}
					} else if err := c.VerifyNUpdateBPFProgram(&bpfProg, ifaceName, direction); err != nil {
						return fmt.Errorf("failed to update BPF Program: %w", err)
					}
				case models.EgressType:
					if c.EgressTCBpfs[ifaceName] == nil {
						if bpfProg.AdminStatus == models.Enabled {
							c.EgressTCBpfs[ifaceName] = list.New()
							if err := c.VerifyAndStartTCRootProgram(ifaceName, direction); err != nil {
								return fmt.Errorf("failed to chain ingress tc bpf programs: %w", err)
							}
							if err := c.PushBackAndStartBPF(&bpfProg, ifaceName, direction); err != nil {
								return fmt.Errorf("failed to update BPF Program: %w", err)
							}
						}
					} else if err := c.VerifyNUpdateBPFProgram(&bpfProg, ifaceName, direction); err != nil {
						return fmt.Errorf("failed to update BPF Program: %w", err)
					}
				}
			}
		}
	}

	c.configs.Store(string(key), cfgbpfProgs)
	return nil
}

func (c *NFConfigs) Get(key string) ([]*models.L3afDNFConfigDetail, bool) {
	val, ok := c.configs.Load(key)
	if !ok {
		return nil, false
	}
	bpfList, ok := val.([]*models.L3afDNFConfigDetail)
	if !ok {
		logs.Errorf("NFConfigs value type is wrong")
		return nil, false
	}
	return bpfList, true
}

// This method to stop all the network functions and delete elements in the list
func (c *NFConfigs) Close(ctx context.Context) error {
	ticker := time.NewTicker(shutdownInterval)
	defer ticker.Stop()
	for {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ifaceName, _ := range c.IngressXDPBpfs {
				if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.XDPIngressType, models.XDPType); err != nil {
					logs.Warningf("failed to Close Ingress XDP BPF Program ", err)
				}
				delete(c.IngressXDPBpfs, ifaceName)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for ifaceName, _ := range c.IngressTCBpfs {
				if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.IngressType, models.TCType); err != nil {
					logs.Warningf("failed to Close Ingress TC BPF Program ", err)
				}
				delete(c.IngressTCBpfs, ifaceName)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for ifaceName, _ := range c.EgressTCBpfs {
				if err := c.StopNRemoveAllBPFPrograms(ifaceName, models.EgressType, models.TCType); err != nil {
					logs.Warningf("failed to Close Egress TC BPF Program ", err)
				}
				delete(c.EgressTCBpfs, ifaceName)
			}
		}()

		// Wait for all NF's to stop.
		wg.Wait()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Check for XDP programs are not loaded then initialise the array
// Check for XDP root program is running for a interface. if not loaded it
func (c *NFConfigs) VerifyAndStartXDPRootProgram(ifaceName, direction string) error {

	// chaining is disabled nothing to do
	if !c.hostConfig.BpfChainingEnabled {
		return nil
	}

	if c.IngressXDPBpfs[ifaceName].Len() == 0 {
		if err := VerifyNMountBPFFS(); err != nil {
			return fmt.Errorf("failed to mount bpf file system")
		}
		rootBpf, err := LoadRootProgram(ifaceName, direction, models.XDPType, c.hostConfig)
		if err != nil {
			return fmt.Errorf("failed to load %s xdp root program: %w", direction, err)
		}
		logs.Infof("ingress xdp root program attached")
		c.IngressXDPBpfs[ifaceName].PushFront(rootBpf)
	}

	return nil
}

// Check for TC root program is running for a interface. If not start it
func (c *NFConfigs) VerifyAndStartTCRootProgram(ifaceName, direction string) error {

	// Check for chaining flag
	if !c.hostConfig.BpfChainingEnabled {
		return nil
	}

	if direction == models.IngressType {
		if c.IngressTCBpfs[ifaceName].Len() == 0 { //Root program is not running start then
			rootBpf, err := LoadRootProgram(ifaceName, direction, models.TCType, c.hostConfig)
			if err != nil {
				return fmt.Errorf("failed to load %s tc root program: %w", direction, err)
			}
			logs.Infof("ingress tc root program attached")
			c.IngressTCBpfs[ifaceName].PushFront(rootBpf)
		}
	} else {
		if c.EgressTCBpfs[ifaceName].Len() == 0 { //Root program is not running start then
			rootBpf, err := LoadRootProgram(ifaceName, direction, models.TCType, c.hostConfig)
			if err != nil {
				return fmt.Errorf("failed to load %s tc root program: %w", direction, err)
			}
			logs.Infof("egress tc root program attached")
			c.EgressTCBpfs[ifaceName].PushFront(rootBpf)
		}
	}

	return nil
}

// This method inserts the element at the end of the list
func (c *NFConfigs) PushBackAndStartBPF(bpfProg *models.BPFProgram, ifaceName, direction string) error {

	bpf := NewBpfProgram(*bpfProg, c.hostConfig.BPFLogDir)
	var bpfList *list.List

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default: // we should never reach here
		return fmt.Errorf("unknown direction type")
	}

	if err := c.DownloadAndStartBPFProgram(bpfList.PushBack(bpf), ifaceName, direction); err != nil {
		return fmt.Errorf("failed to download and start the BPF %s iface %s direction %s", bpfProg.Name, ifaceName, direction)
	}

	return nil
}

func (c *NFConfigs) DownloadAndStartBPFProgram(element *list.Element, ifaceName, direction string) error {

	if element == nil {
		return fmt.Errorf("element is nil pointer")
	}

	bpf := element.Value.(*BPF)

	if element.Prev() != nil {
		prevBPF := element.Prev().Value.(*BPF)
		bpf.PrevMapName = prevBPF.Program.MapName
		logs.Infof("DownloadAndStartBPFProgram : program name %s previous prorgam map name: %s", bpf.Program.Name, bpf.PrevMapName)
	}

	if err := bpf.VerifyAndGetArtifacts(c.hostConfig); err != nil {
		return fmt.Errorf("failed to get artifacts %s with error: %w", bpf.Program.Artifact, err)
	}

	if err := bpf.Start(ifaceName, direction, c.hostConfig.BpfChainingEnabled); err != nil {
		return fmt.Errorf("failed to start bpf program %s with error: %w", bpf.Program.Name, err)
	}

	return nil
}

// Stopping all programs in reverse order
func (c *NFConfigs) StopNRemoveAllBPFPrograms(ifaceName, direction, ebpfType string) error {

	var bpfList *list.List

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default: // we should never reach here
		return fmt.Errorf("unknown direction type")
	}

	if bpfList == nil {
		logs.Warningf("no %s ebpf programs to stop", direction)
		return nil
	}

	for e := bpfList.Back(); e != nil; {
		data := e.Value.(*BPF)
		if err := data.Stop(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to stop program %s", data.Program.Name)
		}
		prevBPF := e.Prev()
		bpfList.Remove(e)
		e = prevBPF
	}

	return nil
}

// This method checks the following conditions
// 1. BPF Program already running with no change
// 2. BPF Program running but needs to stop (admin_status == disabled)
// 3. BPF Program running but needs version update
// 4. BPF Program running but position change (seq_id change)
// 5. BPF Program not running but needs to start.

func (c *NFConfigs) VerifyNUpdateBPFProgram(bpfProg *models.BPFProgram, ifaceName, direction string) (error) {

	var bpfList *list.List;
	if bpfProg == nil {
		return nil
	}

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)

		if strings.Compare(data.Program.Name, bpfProg.Name) != 0 {
			continue
		}

		if reflect.DeepEqual(data.Program, *bpfProg) == true {
			logs.Debugf("VerifyNUpdateBPFProgram : DeepEqual Matched Name %s ", data.Program.Name)
			// Nothing to do
			return nil;
		}

		// Admin status change - disabled
		if data.Program.AdminStatus != bpfProg.AdminStatus {
			logs.Infof("verifyNUpdateBPFProgram :admin_status change detected - disabling the program %s", data.Program.Name)
			// get the program fd of next program from the map
			nextProgFD, err := data.GetProgFDofNext()
			if err != nil {
				return fmt.Errorf("failed to fetch next program FD from the bpf map %#v", err)
			}

			if err := data.Stop(ifaceName, direction); err != nil {
				return fmt.Errorf("failed to stop to on admin_status change BPF %s iface %s direction %s admin_status %s", bpfProg.Name, ifaceName, direction, bpfProg.AdminStatus)
			}

			tmpNextBPF := e.Next()
			tmpPreviousBPF := e.Prev()
			bpfList.Remove(e)
			if tmpNextBPF != nil { // relink the next element and restart
				tmpPrevbpf := tmpNextBPF.Prev().Value.(*BPF)
				tmpNextBPF.Value.(*BPF).PrevMapName = tmpPrevbpf.Program.MapName
				if err := tmpNextBPF.Value.(*BPF).PutProgFDofNext(nextProgFD); err != nil {
					return fmt.Errorf("failed to update program fd of next program %s", bpfProg.Name)
				}
			}
			// Check if list contains root program only then stop the root program.
			if tmpPreviousBPF.Prev() == nil && tmpPreviousBPF.Next() == nil {
				logs.Infof("no network functions are running, stopping root program")
				if c.hostConfig.BpfChainingEnabled {
					if err := c.StopRootProgram(ifaceName, direction); err != nil {
						return fmt.Errorf("failed to stop to root program  %s iface %s direction %s", bpfProg.Name, ifaceName, direction)
					}
				}
			}
			return nil
		}

		if data.Program.CfgVersion != bpfProg.CfgVersion {

			// Update CfgVersion
			data.Program.CfgVersion = bpfProg.CfgVersion

			// Seq ID Change
			if data.Program.SeqID != bpfProg.SeqID {
				logs.Infof("VerifyNUpdateBPFProgram : seq id change detected current seq id %d new seq id %d", data.Program.SeqID, bpfProg.SeqID)
				tmpBPF := e
				tmpPrevBPF := e.Prev()

				// Update seq id
				data.Program.SeqID = bpfProg.SeqID

				if tmpBPF.Value.(*BPF).PrevMapName != tmpPrevBPF.Value.(*BPF).Program.MapName {
					if err := c.MoveToLocation(e, ifaceName, direction); err != nil {
						return fmt.Errorf("failed to move to new position in the chain BPF %s version %s iface %s direction %s", bpfProg.Name, bpfProg.Version, ifaceName, direction)
					}
					if tmpBPF.Next() != nil {
						if tmpBPF.Value.(*BPF).Program.MapName != tmpBPF.Next().Value.(*BPF).PrevMapName {
							tmpBPF.Next().Value.(*BPF).PrevMapName = tmpBPF.Value.(*BPF).Program.MapName
							if err := tmpBPF.Value.(*BPF).PutProgFDofNext(tmpBPF.Next().Value.(*BPF).ProgFD); err != nil {
								return fmt.Errorf("Update of ProgFD on seq change failed %w", err)
							}
						}
					}
				}
			}

			// monitor maps change
			if reflect.DeepEqual(data.Program.MonitorMaps, bpfProg.MonitorMaps) != true {
				logs.Infof("monitor map list is mismatched")
				copy(data.Program.MonitorMaps, bpfProg.MonitorMaps)
			}

			// monitor maps change
			if reflect.DeepEqual(data.Program.MapArgs, bpfProg.MapArgs) != true {
				logs.Infof("maps_args are mismatched")
				copy(data.Program.MapArgs, bpfProg.MapArgs)
				data.Update(direction)
			}
			// Version Change
			if data.Program.Version != bpfProg.Version || reflect.DeepEqual(data.Program.StartArgs, bpfProg.StartArgs) != true {
				logs.Infof("VerifyNUpdateBPFProgram : version update initiated - current version %s new version %s", data.Program.Version, bpfProg.Version)

				nextProgFD, err := data.GetProgFDofNext()
				if err != nil {
					return fmt.Errorf("failed to fetch next program FD from the bpf map")
				}
				if err := data.Stop(ifaceName, direction); err != nil {
					return fmt.Errorf("failed to stop older version of network function BPF %s iface %s direction %s version %s", bpfProg.Name, ifaceName, direction, bpfProg.Version)
				}
				data.Program = *bpfProg
				//logs.Infof("sleeping 30 seconds")
				//time.Sleep(30 * time.Second)
				if err := c.DownloadAndStartBPFProgram(e, ifaceName, direction); err != nil {
					return fmt.Errorf("failed to download and start newer version of network function BPF %s version %s iface %s direction %s", bpfProg.Name, bpfProg.Version, ifaceName, direction)
				}
				data.PutProgFDofNext(nextProgFD)
			}
			return nil
		}
	}

	// if not found in the list.
	if err := c.InsertAndStartBPFProgram(bpfProg, ifaceName, direction); err != nil {
		return fmt.Errorf("failed to insert and start BPFProgram to new location BPF %s version %s iface %s direction %s", bpfProg.Name, bpfProg.Version, ifaceName, direction)
	}

	return nil
}

func (c *NFConfigs) MoveToLocation(element *list.Element, ifaceName, direction string) (error) {

	var bpfList *list.List;
	if element == nil {
		return fmt.Errorf("MoveToLocation - element is nil")
	}

	bpf := element.Value.(*BPF)
	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	if bpfList == nil {
		logs.Warningf("ebpf program list is empty")
		return nil
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if data.Program.SeqID >= bpf.Program.SeqID {
			bpfList.MoveBefore(element, e)
			logs.Infof("MoveToLocation : Moved ...")
			return nil
		}
	}

	return fmt.Errorf("element not found in the list")
}

// InsertAndStartBPFProgram method for tc programs
func (c *NFConfigs) InsertAndStartBPFProgram(bpfProg *models.BPFProgram, ifaceName, direction string) (error) {

	var bpfList *list.List;
	if bpfProg == nil {
		return fmt.Errorf("InsertAndStartBPFProgram - bpf program is nil")
	}

	if bpfProg.AdminStatus == models.Disabled {
		return nil
	}

	bpf := NewBpfProgram(*bpfProg, c.hostConfig.BPFLogDir)

	switch direction {
	case models.XDPIngressType:
		bpfList = c.IngressXDPBpfs[ifaceName]
	case models.IngressType:
		bpfList = c.IngressTCBpfs[ifaceName]
	case models.EgressType:
		bpfList = c.EgressTCBpfs[ifaceName]
	default:
		return fmt.Errorf("unknown direction type")
	}

	if bpfList == nil {
		logs.Warningf("%s program list is empty", direction)
		return nil
	}

	for e := bpfList.Front(); e != nil; e = e.Next() {
		data := e.Value.(*BPF)
		if data.Program.SeqID >= bpfProg.SeqID {
			tmpBPF := bpfList.InsertBefore(bpf, e)
			if err := c.DownloadAndStartBPFProgram(tmpBPF, ifaceName, direction); err != nil {
				return fmt.Errorf("failed to download and start network function %s version %s iface %s direction %s", bpfProg.Name, bpfProg.Version, ifaceName, direction)
			}

			if tmpBPF.Next() != nil {
				if tmpBPF.Value.(*BPF).Program.MapName != tmpBPF.Next().Value.(*BPF).PrevMapName {
					tmpBPF.Next().Value.(*BPF).PrevMapName = tmpBPF.Value.(*BPF).Program.MapName
					if err := tmpBPF.Value.(*BPF).PutProgFDofNext(tmpBPF.Next().Value.(*BPF).ProgFD); err != nil {
						return fmt.Errorf("Update of ProgFD on seq change failed %w", err)
					}
				}
			}

			return nil
		}
	}

	// insert at the end
	if err := c.PushBackAndStartBPF(bpfProg, ifaceName, direction); err != nil {
		return fmt.Errorf("failed to push back and start network function %s version %s iface %s direction %s", bpfProg.Name, bpfProg.Version, ifaceName, direction)
	}

	return nil
}

// This method stops the root program, removes the root node from the list and reset the list to nil
func (c *NFConfigs) StopRootProgram(ifaceName, direction string) (error) {

	switch direction {
	case models.XDPIngressType:
		if c.IngressXDPBpfs[ifaceName] == nil {
			logs.Warningf("xdp root program is not running")
			return nil
		}

		if err := c.IngressXDPBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to stop xdp root program iface %s", ifaceName)
		}
		c.IngressXDPBpfs[ifaceName].Remove(c.IngressXDPBpfs[ifaceName].Front())
		c.IngressXDPBpfs[ifaceName] = nil
	case models.IngressType:
		if c.IngressTCBpfs[ifaceName] == nil {
			logs.Warningf("tc root program %s not running", direction)
			return nil
		}
		if err := c.IngressTCBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to stop ingress tc root program on interface %s", ifaceName)
		}
		c.IngressTCBpfs[ifaceName].Remove(c.IngressTCBpfs[ifaceName].Front())
		c.IngressTCBpfs[ifaceName] = nil
	case models.EgressType:
		if c.EgressTCBpfs[ifaceName] == nil {
			logs.Warningf("tc root program %s not running", direction)
			return nil
		}
		if err := c.EgressTCBpfs[ifaceName].Front().Value.(*BPF).Stop(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to stop egress tc root program on interface %s", ifaceName)
		}
		c.EgressTCBpfs[ifaceName].Remove(c.EgressTCBpfs[ifaceName].Front())
		c.EgressTCBpfs[ifaceName] = nil
	default:
		return fmt.Errorf("unknown direction type")
	}

	return nil
}

// Mounting bpf filesystem
func VerifyNMountBPFFS() error {
	dstPath := "/sys/fs/bpf"
	srcPath := "bpffs"
	fstype := "bpf"
	flags  := 0

	mnts, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to read procfs: %v", err)
	}

	if strings.Contains(string(mnts), dstPath) == false {
		logs.Warningf("bpf filesystem is not mounted going to mount")
		if err = syscall.Mount(srcPath, dstPath, fstype, uintptr(flags), ""); err != nil {
			return fmt.Errorf("unable to mount %s at %s: %s", srcPath, dstPath, err)
		}
	}
	return nil
}
