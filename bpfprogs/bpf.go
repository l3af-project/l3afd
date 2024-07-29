// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package bpfprogs provides primitives for BPF programs / Network Functions.
package bpfprogs

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"container/ring"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/stats"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	ps "github.com/mitchellh/go-ps"
	"github.com/rs/zerolog/log"
)

var (
	execCommand           = exec.Command
	copyBufPool sync.Pool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}
)

//lint:ignore U1000 avoid false linter error on windows, since this variable is only used in linux code
const executePerm uint32 = 0111
const bpfStatus string = "RUNNING"
const httpScheme string = "http"
const httpsScheme string = "https"
const fileScheme string = "file"

// BPF defines run time details for BPFProgram.
type BPF struct {
	Program           models.BPFProgram
	Cmd               *exec.Cmd                 `json:"-"`
	FilePath          string                    // Binary file path
	RestartCount      int                       // To track restart count
	PrevMapNamePath   string                    // Previous Map name with path to link
	MapNamePath       string                    // Map name with path
	ProgID            ebpf.ProgramID            // eBPF Program ID
	BpfMaps           map[string]BPFMap         // Config maps passed as map-args, Map name is Key
	MetricsBpfMaps    map[string]*MetricsBPFMap // Metrics map name+key+aggregator is key
	Ctx               context.Context           `json:"-"`
	Done              chan bool                 `json:"-"`
	ProgMapCollection *ebpf.Collection          `json:"_"` // eBPF Collection reference
	ProgMapID         ebpf.MapID                // Prog map id
	PrevProgMapID     ebpf.MapID                // Prev prog map id
	HostConfig        *config.Config
	XDPLink           link.Link `json:"-"` // handle xdp link object
	ProbeLinks        []*link.Link
}

func NewBpfProgram(ctx context.Context, program models.BPFProgram, conf *config.Config, ifaceName string) *BPF {

	var progMapFilePath string
	if len(program.MapName) > 0 {
		if program.ProgType == models.XDPType {
			progMapFilePath = filepath.Join(conf.BpfMapDefaultPath, ifaceName, program.MapName)
		} else if program.ProgType == models.TCType {
			progMapFilePath = filepath.Join(conf.BpfMapDefaultPath, models.TCMapPinPath, ifaceName, program.MapName)
		}
		if strings.Contains(progMapFilePath, "..") {
			log.Error().Msgf("program map file contains relative path %s", progMapFilePath)
			return nil
		}
	}

	bpf := &BPF{
		Program:        program,
		RestartCount:   0,
		Cmd:            nil,
		FilePath:       "",
		BpfMaps:        make(map[string]BPFMap, 0),
		MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
		Ctx:            ctx,
		Done:           nil,
		HostConfig:     conf,
		MapNamePath:    progMapFilePath,
	}

	return bpf
}

// LoadRootProgram - Loading the Root Program for a given interface.
func LoadRootProgram(ifaceName string, direction string, progType string, conf *config.Config) (*BPF, error) {

	log.Info().Msgf("LoadRootProgram iface %s direction %s progType %s", ifaceName, direction, progType)
	var rootProgBPF *BPF

	switch progType {
	case models.XDPType:
		rootProgBPF = &BPF{
			Program: models.BPFProgram{
				Name:              conf.XDPRootPackageName,
				Artifact:          conf.XDPRootArtifact,
				MapName:           conf.XDPRootMapName,
				Version:           conf.XDPRootVersion,
				UserProgramDaemon: false,
				AdminStatus:       models.Enabled,
				ProgType:          models.XDPType,
				SeqID:             0,
				StartArgs:         map[string]interface{}{},
				StopArgs:          map[string]interface{}{},
				StatusArgs:        map[string]interface{}{},
				ObjectFile:        conf.XDPRootObjectFile,
				EntryFunctionName: conf.XDPRootEntryFunctionName,
			},
			RestartCount:    0,
			Cmd:             nil,
			FilePath:        "",
			PrevMapNamePath: "",
			HostConfig:      conf,
			MapNamePath:     filepath.Join(conf.BpfMapDefaultPath, ifaceName, conf.XDPRootMapName),
			XDPLink:         nil,
		}
	case models.TCType:
		rootProgBPF = &BPF{
			Program: models.BPFProgram{
				Name:              conf.TCRootPackageName,
				Artifact:          conf.TCRootArtifact,
				Version:           conf.TCRootVersion,
				UserProgramDaemon: false,
				AdminStatus:       models.Enabled,
				ProgType:          models.TCType,
				StartArgs:         map[string]interface{}{},
				StopArgs:          map[string]interface{}{},
				StatusArgs:        map[string]interface{}{},
			},
			RestartCount:    0,
			Cmd:             nil,
			FilePath:        "",
			PrevMapNamePath: "",
			HostConfig:      conf,
		}
		if direction == models.IngressType {
			rootProgBPF.Program.MapName = conf.TCRootIngressMapName
			rootProgBPF.Program.ObjectFile = conf.TCRootIngressObjectFile
			rootProgBPF.Program.EntryFunctionName = conf.TCRootIngressEntryFunctionName
		} else if direction == models.EgressType {
			rootProgBPF.Program.MapName = conf.TCRootEgressMapName
			rootProgBPF.Program.ObjectFile = conf.TCRootEgressObjectFile
			rootProgBPF.Program.EntryFunctionName = conf.TCRootEgressEntryFunctionName
		}
		rootProgBPF.MapNamePath = filepath.Join(conf.BpfMapDefaultPath, models.TCMapPinPath, ifaceName, rootProgBPF.Program.MapName)
	default:
		return nil, fmt.Errorf("unknown direction %s for root program in iface %s", direction, ifaceName)
	}

	if err := rootProgBPF.VerifyAndGetArtifacts(conf); err != nil {
		log.Error().Err(err).Msg("failed to get root artifacts")
		return nil, err
	}

	// On l3afd crashing scenario verify root program are unloaded properly by checking existence of persisted maps
	// if map file exists then root program didn't clean up pinned map files
	if fileExists(rootProgBPF.MapNamePath) {
		log.Warn().Msgf("previous instance of root program %s persisted map %s file exists", rootProgBPF.Program.Name, rootProgBPF.MapNamePath)
		if err := rootProgBPF.RemoveRootProgMapFile(ifaceName); err != nil {
			log.Warn().Err(err).Msgf("previous instance of root program %s map file not removed successfully - %s ", rootProgBPF.Program.Name, rootProgBPF.MapNamePath)
		}
	}

	if progType == models.XDPType {
		rlimit.RemoveMemlock()
		if err := rootProgBPF.LoadXDPAttachProgram(ifaceName); err != nil {
			return nil, fmt.Errorf("failed to load xdp root program on iface \"%s\" name %s direction %s with err %w", ifaceName, rootProgBPF.Program.Name, direction, err)
		}
	} else if progType == models.TCType {
		if err := rootProgBPF.LoadTCAttachProgram(ifaceName, direction); err != nil {
			return nil, fmt.Errorf("failed to load tc root program on iface \"%s\" name %s direction %s with err %w", ifaceName, rootProgBPF.Program.Name, direction, err)
		}
	}

	return rootProgBPF, nil
}

// Stop the NF process if running outside l3afd
func StopExternalRunningProcess(processName string) error {
	// validate process name
	if len(processName) < 1 {
		return fmt.Errorf("process name can not be empty")
	}

	// process names are truncated to 15 chars
	psName := processName
	if len(processName) > 15 {
		psName = processName[:15]
	}

	myPid := os.Getpid()
	processList, err := ps.Processes()
	if err != nil {
		return fmt.Errorf("failed to fetch processes list with err %w", err)
	}
	log.Info().Msgf("Searching for process %s and not ppid %d", processName, myPid)
	for _, process := range processList {
		if strings.Contains(process.Executable(), psName) {
			if process.PPid() != myPid {
				log.Warn().Msgf("found process id %d name %s ppid %d, stopping it", process.Pid(), process.Executable(), process.PPid())
				osProcess, err := os.FindProcess(process.Pid())
				if err == nil {
					err = osProcess.Kill()
				}
				if err != nil {
					return fmt.Errorf("external BPFProgram stop failed with error: %w", err)
				}
			}
		}
	}
	return nil
}

// Stop returns the last error seen, but stops bpf program.
// Stops the user programs if any, and unloads the BPF program.
// Clean up all map handles.
// Verify next program pinned map file is removed
func (b *BPF) Stop(ifaceName, direction string, chain bool) error {
	if b.Program.UserProgramDaemon && b.Cmd == nil {
		return fmt.Errorf("BPFProgram is not running %s", b.Program.Name)
	}

	log.Info().Msgf("Stopping BPF Program - %s", b.Program.Name)

	// Removing maps
	for key, val := range b.BpfMaps {
		log.Debug().Msgf("removing BPF maps %s value map %#v", key, val)
		delete(b.BpfMaps, key)
	}

	// Removing Metrics maps
	for key, val := range b.MetricsBpfMaps {
		log.Debug().Msgf("removing metric bpf maps %s value %#v", key, val)
		delete(b.MetricsBpfMaps, key)
	}

	// Stop BPF configs
	if len(b.Program.CmdConfig) > 0 && len(b.Program.ConfigFilePath) > 0 {
		log.Info().Msgf("Stopping BPF configs %s ", b.Program.Name)
		b.Done <- true
	}

	// Reset ProgID
	b.ProgID = 0

	stats.Incr(stats.BPFStopCount, b.Program.Name, direction, ifaceName)

	// Setting NFRunning to 0, indicates not running
	stats.SetWithVersion(0.0, stats.BPFRunning, b.Program.Name, b.Program.Version, direction, ifaceName)

	// Stop User Programs if any
	if len(b.Program.CmdStop) < 1 && b.Program.UserProgramDaemon {
		// Loaded using user program
		if err := b.ProcessTerminate(); err != nil {
			return fmt.Errorf("BPFProgram %s process terminate failed with error: %w", b.Program.Name, err)
		}
		if b.Cmd != nil {
			if err := b.Cmd.Wait(); err != nil {
				log.Error().Err(err).Msgf("cmd wait at stopping bpf program %s errored", b.Program.Name)
			}
			b.Cmd = nil
		}
	} else if len(b.Program.CmdStop) > 0 && b.Program.UserProgramDaemon {
		cmd := filepath.Join(b.FilePath, b.Program.CmdStop)

		if err := AssertExecutable(cmd); err != nil {
			return fmt.Errorf("no executable permissions on %s - error %w", b.Program.CmdStop, err)
		}

		args := make([]string, 0, len(b.Program.StopArgs)<<1)
		if len(ifaceName) > 0 {
			args = append(args, "--iface="+ifaceName) // detaching from iface
		}
		if len(direction) > 0 {
			args = append(args, "--direction="+direction) // xdpingress or ingress or egress
		}
		for k, val := range b.Program.StopArgs {
			if v, ok := val.(string); !ok {
				err := fmt.Errorf("stop args is not a string for the bpf program %s", b.Program.Name)
				log.Error().Err(err).Msgf("failed to convert stop args value into string for program %s", b.Program.Name)
				return err
			} else {
				args = append(args, "--"+k+" ="+v)
			}
		}

		log.Info().Msgf("bpf program stop command : %s %v", cmd, args)
		prog := execCommand(cmd, args...)
		if err := prog.Run(); err != nil {
			log.Warn().Err(err).Msgf("l3afd : Failed to stop the program %s", b.Program.CmdStop)
		}
		b.Cmd = nil
	}

	// unload the BPF programs
	if allInterfaces, err := getHostInterfaces(); err != nil {
		errOut := fmt.Errorf("failed get interfaces in Stop Function: %v", err)
		log.Error().Err(errOut)
		return errOut
	} else {
		if _, ok := allInterfaces[ifaceName]; ok {
			if b.ProgMapCollection != nil {
				if err := b.UnloadProgram(ifaceName, direction); err != nil {
					return fmt.Errorf("BPFProgram %s unload failed on interface %s with error: %w", b.Program.Name, ifaceName, err)
				}
				log.Info().Msgf("%s => %s direction => %s - program is unloaded/detached successfully", ifaceName, b.Program.Name, direction)
			}
		} else {
			if err := b.RemovePinnedFiles(ifaceName); err != nil {
				log.Error().Err(err).Msgf("stop user program - failed to remove map files %s", b.Program.Name)
				return fmt.Errorf("stop user program - failed to remove map files %s", b.Program.Name)
			}
		}
	}

	if err := b.VerifyCleanupMaps(chain); err != nil {
		log.Error().Err(err).Msgf("stop user program - failed to remove map files %s", b.Program.Name)
		return fmt.Errorf("stop user program - failed to remove map files %s", b.Program.Name)
	}

	return nil
}

// Start returns the last error seen, but starts bpf program.
// Here initially prevprogmap entry is removed and passed to the bpf program
// After starting the user program, will update the kernel progam fd into prevprogram map.
// This method waits till prog fd entry is updated, else returns error assuming kernel program is not loaded.
// It also verifies the next program pinned map is created or not.
func (b *BPF) Start(ifaceName, direction string, chain bool) error {
	if b.FilePath == "" {
		return errors.New("no program binary path found")
	}

	if len(b.Program.CmdStart) > 0 {
		// Verify other instance is running
		if err := StopExternalRunningProcess(b.Program.CmdStart); err != nil {
			return fmt.Errorf("failed to stop external instance of the program %s with error : %w", b.Program.CmdStart, err)
		}
	}

	// Making sure old map entry is removed before passing the prog fd map to the program.
	if len(b.PrevMapNamePath) > 0 {
		if err := b.RemovePrevProgFD(); err != nil {
			log.Error().Err(err).Msgf("ProgramMap %s entry removal failed", b.PrevMapNamePath)
		}
	}

	// Both xdp and tc are loaded using the same mechanism.
	if len(b.Program.ObjectFile) > 0 {
		if chain {
			if err := b.LoadBPFProgramChain(ifaceName, direction); err != nil {
				return fmt.Errorf("loading bpf program %s - error %w", b.Program.Name, err)
			}
		} else {
			if err := b.AttachBPFProgram(ifaceName, direction); err != nil {
				return fmt.Errorf("attaching bpf program %s - error %w", b.Program.Name, err)
			}
		}
	} else {
		log.Info().Msgf("bpf program object file is not defined - %s", b.Program.Name)
	}

	log.Info().Msgf("successfully Loaded & Attached %s in direction %s on interface %s", b.Program.Name, direction, ifaceName)
	// Start user program before loading
	if len(b.Program.CmdStart) > 0 {
		if err := b.StartUserProgram(ifaceName, direction, chain); err != nil {
			return fmt.Errorf("user program startup failed %s - error %w", b.Program.CmdStart, err)
		}
	}

	// making sure program fd map pinned file is created
	if err := b.VerifyPinnedProgMap(chain, true); err != nil {
		return fmt.Errorf("failed to find pinned file %s  %w", b.MapNamePath, err)
	}

	// BPF map config values
	if len(b.Program.MapArgs) > 0 {
		if err := b.UpdateBPFMaps(ifaceName, direction); err != nil {
			log.Error().Err(err).Msg("failed to update ebpf program BPF maps")
			return fmt.Errorf("failed to update ebpf program BPF maps %w", err)
		}
	}

	// Update args config values
	if len(b.Program.UpdateArgs) > 0 {
		if err := b.UpdateArgs(ifaceName, direction); err != nil {
			log.Error().Err(err).Msg("failed to update ebpf program config update")
			return fmt.Errorf("failed to update ebpf program config update %w", err)
		}
	}

	// Fetch when prev program map is updated only when loaded using user program
	if len(b.PrevMapNamePath) > 0 && b.ProgMapCollection == nil {
		var err error
		// retry 10 times to verify entry is created
		for i := 0; i < 10; i++ {
			b.ProgID, err = b.GetProgID()
			if err == nil {
				break
			}

			log.Warn().Msg("failed to fetch the program ID, retrying after a second ... ")
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			log.Error().Err(err).Msg("failed to fetch ebpf program FD")
			return fmt.Errorf("failed to fetch ebpf program FD %w", err)
		}
	}

	// BPFconfigs
	if len(b.Program.CmdConfig) > 0 && len(b.Program.ConfigFilePath) > 0 {
		log.Info().Msgf("eBPF program specific config monitoring - %s", b.Program.ConfigFilePath)
		b.Done = make(chan bool)
		go b.RunBPFConfigs()
	}

	stats.Incr(stats.BPFStartCount, b.Program.Name, direction, ifaceName)
	stats.Set(float64(time.Now().Unix()), stats.BPFStartTime, b.Program.Name, direction, ifaceName)

	userProgram, bpfProgram, err := b.isRunning()
	if !userProgram && !bpfProgram {
		log.Error().Err(err).Msg("eBPF program failed to start")
		return fmt.Errorf("bpf program %s failed to start %w", b.Program.Name, err)
	}

	log.Info().Msgf("BPF program - %s started Program ID %d", b.Program.Name, uint32(b.ProgID))
	return nil
}

// UpdateBPFMaps - Update the config ebpf maps via map arguments
func (b *BPF) UpdateBPFMaps(ifaceName, direction string) error {
	for _, val := range b.Program.MapArgs {
		bpfMap, ok := b.BpfMaps[val.Name]
		if !ok {
			if err := b.AddBPFMap(val.Name); err != nil {
				return err
			}
			bpfMap = b.BpfMaps[val.Name]
		}
		for _, v := range val.Args {
			log.Info().Msgf("Update map args key %v val %v", v.Key, v.Value)
			bpfMap.Update(v.Key, v.Value)
		}
		if err := bpfMap.RemoveMissingKeys(val.Args); err != nil {
			return fmt.Errorf("failed to remove missing entries of map %s with err %w", val.Name, err)
		}
	}
	stats.Incr(stats.BPFUpdateCount, b.Program.Name, direction, ifaceName)
	return nil
}

// Update config arguments using user program
func (b *BPF) UpdateArgs(ifaceName, direction string) error {
	if b.FilePath == "" {
		return errors.New("update - no program binary path found")
	}

	cmd := filepath.Join(b.FilePath, b.Program.CmdUpdate)
	// Validate
	if err := AssertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %w", b.Program.CmdUpdate, err)
	}

	args := make([]string, 0, len(b.Program.UpdateArgs)<<1)
	args = append(args, "--iface="+ifaceName)       // attaching to interface
	args = append(args, "--direction="+direction)   // direction xdpingress or ingress or egress
	args = append(args, "--cmd="+models.UpdateType) // argument cmd to update configs

	if len(b.HostConfig.BPFLogDir) > 1 {
		args = append(args, "--log-dir="+b.HostConfig.BPFLogDir)
	}

	for k, val := range b.Program.UpdateArgs {
		if v, ok := val.(string); !ok {
			err := fmt.Errorf("update args is not a string for the ebpf program %s", b.Program.Name)
			log.Error().Err(err).Msgf("failed to convert update args value into string for program %s", b.Program.Name)
			return err
		} else {
			args = append(args, "--"+k+"="+v)
		}
	}

	log.Info().Msgf("BPF Program update command : %s %v", cmd, args)
	UpdateCmd := execCommand(cmd, args...)
	if err := UpdateCmd.Start(); err != nil {
		stats.Incr(stats.BPFUpdateFailedCount, b.Program.Name, direction, ifaceName)
		customerr := fmt.Errorf("failed to start : %s %v %w", cmd, args, err)
		log.Warn().Err(customerr).Msgf("user mode BPF program failed - %s", b.Program.Name)
		return customerr
	}

	if err := UpdateCmd.Wait(); err != nil {
		stats.Incr(stats.BPFUpdateFailedCount, b.Program.Name, direction, ifaceName)
		return fmt.Errorf("cmd wait at starting of bpf program returned with error %w", err)
	}

	stats.Incr(stats.BPFUpdateCount, b.Program.Name, direction, ifaceName)

	log.Info().Msgf("BPF program - %s config updated", b.Program.Name)
	return nil
}

// Status of user program is running
func (b *BPF) isRunning() (bool, bool, error) {
	userProgram := true
	bpfProgram := false
	var err error

	// CmdStatus should check for user and BPF program
	if len(b.Program.CmdStatus) > 1 {
		cmd := filepath.Join(b.FilePath, b.Program.CmdStatus)

		if err := AssertExecutable(cmd); err != nil {
			userProgram = false
		} else {
			args := make([]string, 0, len(b.Program.StatusArgs)<<1)

			for k, val := range b.Program.StatusArgs {
				if v, ok := val.(string); !ok {
					err = fmt.Errorf("status args is not a string for the ebpf program %s", b.Program.Name)
					log.Warn().Err(err).Msgf("failed to convert status args value into string for program %s", b.Program.Name)
				} else {
					args = append(args, "--"+k+" ="+v)
				}
			}
			prog := execCommand(cmd, args...)
			var out bytes.Buffer
			prog.Stdout = &out
			prog.Stderr = &out
			if err = prog.Run(); err != nil {
				log.Warn().Err(err).Msgf("l3afd : Failed to execute %s", b.Program.CmdStatus)
			}
			outStr, errStr := out.String(), out.String()
			if strings.EqualFold(outStr, bpfStatus) {
				userProgram = true
				bpfProgram = true
			} else {
				userProgram = false
				log.Warn().Msgf("bpf program not running error - %s", errStr)
			}
		}
		return userProgram, bpfProgram, err
	}
	if len(b.Program.CmdStart) > 1 && b.Program.UserProgramDaemon {
		if err := b.VerifyProcessObject(); err != nil {
			userProgram = false
			log.Warn().Err(err).Msgf("process object is not created for command start - %s", b.Program.CmdStart)
		} else {
			userProgram, err = IsProcessRunning(b.Cmd.Process.Pid, b.Program.Name)
			if err != nil {
				log.Warn().Err(err).Msgf("failed to execute command status - %s user program %v", b.Program.CmdStart, userProgram)
			} else {
				userProgram = true
			}
		}
	}

	return userProgram, b.IsLoaded(), err
}

// VerifyAndGetArtifacts -Check binary already exists
func (b *BPF) VerifyAndGetArtifacts(conf *config.Config) error {

	fPath := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version, strings.Split(b.Program.Artifact, ".")[0])
	if _, err := os.Stat(fPath); os.IsNotExist(err) {
		return b.GetArtifacts(conf)
	}

	b.FilePath = fPath
	return nil
}

// GetArtifacts downloads artifacts from the specified eBPF repo
func (b *BPF) GetArtifacts(conf *config.Config) error {

	buf := &bytes.Buffer{}
	isDefaultURLUsed := false
	platform, err := GetPlatform()
	if err != nil {
		return fmt.Errorf("failed to identify platform type: %w", err)
	}

	RepoURL := b.Program.EPRURL
	if len(b.Program.EPRURL) == 0 {
		RepoURL = conf.EBPFRepoURL
		isDefaultURLUsed = true
	}

	URL, err := url.Parse(RepoURL)
	if err != nil {
		if isDefaultURLUsed {
			return fmt.Errorf("unknown ebpf-repo format : %w", err)
		} else {
			return fmt.Errorf("unknown ebpf_package_repo_url format : %w", err)
		}
	}

	URL.Path = path.Join(URL.Path, b.Program.Name, b.Program.Version, platform, b.Program.Artifact)
	log.Info().Msgf("Retrieving artifact - %s", URL)
	switch URL.Scheme {
	case httpsScheme, httpScheme:
		{
			timeOut := time.Duration(conf.HttpClientTimeout) * time.Second
			var netTransport = &http.Transport{
				ResponseHeaderTimeout: timeOut,
			}
			client := http.Client{Transport: netTransport, Timeout: timeOut}

			// Get the data
			resp, err := client.Get(URL.String())
			if err != nil {
				return fmt.Errorf("download failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("get request returned unexpected status code: %d (%s), %d was expected\n\tResponse Body: %s", resp.StatusCode, http.StatusText(resp.StatusCode), http.StatusOK, buf.Bytes())
			}
			buf.ReadFrom(resp.Body)
		}
	case fileScheme:
		{
			if fileExists(URL.Path) {
				f, err := os.Open(URL.Path)
				if err != nil {
					return fmt.Errorf("opening err : %w", err)
				}
				buf.ReadFrom(f)
				f.Close()
			} else {
				return fmt.Errorf("artifact is not found")
			}
		}
	}

	switch artifact := b.Program.Artifact; {
	case strings.HasSuffix(artifact, ".zip"):
		{
			c := bytes.NewReader(buf.Bytes())
			zipReader, err := zip.NewReader(c, int64(c.Len()))
			if err != nil {
				return fmt.Errorf("failed to create zip reader: %w", err)
			}
			tempDir := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version)

			for _, file := range zipReader.File {

				zippedFile, err := file.Open()
				if err != nil {
					return fmt.Errorf("unzip failed: %w", err)
				}
				defer zippedFile.Close()

				extractedFilePath, err := ValidatePath(file.Name, tempDir)
				if err != nil {
					return err
				}

				if file.FileInfo().IsDir() {
					os.MkdirAll(extractedFilePath, file.Mode())
				} else {
					outputFile, err := os.OpenFile(
						extractedFilePath,
						os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
						file.Mode(),
					)
					if err != nil {
						return fmt.Errorf("unzip failed to create file: %w", err)
					}
					defer outputFile.Close()

					buf := copyBufPool.Get().(*bytes.Buffer)
					_, err = io.CopyBuffer(outputFile, zippedFile, buf.Bytes())
					if err != nil {
						return fmt.Errorf("GetArtifacts failed to copy files: %w", err)
					}
					copyBufPool.Put(buf)
				}
			}
			newDir := strings.Split(b.Program.Artifact, ".")
			b.FilePath = filepath.Join(tempDir, newDir[0])
			return nil
		}
	case strings.HasSuffix(b.Program.Artifact, ".tar.gz"):
		{
			archive, err := gzip.NewReader(buf)
			if err != nil {
				return fmt.Errorf("failed to create Gzip reader: %w", err)
			}
			defer archive.Close()
			tarReader := tar.NewReader(archive)
			tempDir := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version)

			for {
				header, err := tarReader.Next()

				if err == io.EOF {
					break
				} else if err != nil {
					return fmt.Errorf("untar failed: %w", err)
				}

				fPath, err := ValidatePath(header.Name, tempDir)
				if err != nil {
					return err
				}

				info := header.FileInfo()
				if info.IsDir() {
					if err = os.MkdirAll(fPath, info.Mode()); err != nil {
						return fmt.Errorf("untar failed to create directories: %w", err)
					}
					continue
				}

				file, err := os.OpenFile(fPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
				if err != nil {
					return fmt.Errorf("untar failed to create file: %w", err)
				}
				defer file.Close()

				buf := copyBufPool.Get().(*bytes.Buffer)
				_, err = io.CopyBuffer(file, tarReader, buf.Bytes())
				if err != nil {
					return fmt.Errorf("GetArtifacts failed to copy files: %w", err)
				}
				copyBufPool.Put(buf)
			}
			newDir := strings.Split(b.Program.Artifact, ".")
			b.FilePath = filepath.Join(tempDir, newDir[0])
			return nil
		}
	default:
		return fmt.Errorf("unknown artifact format")
	}
}

// create rules file
func (b *BPF) createUpdateRulesFile(direction string) (string, error) {

	if len(b.Program.RulesFile) < 1 {
		return "", fmt.Errorf("RulesFile name is empty")
	}

	fileName := path.Join(b.FilePath, direction, b.Program.RulesFile)

	if err := os.WriteFile(fileName, []byte(b.Program.Rules), 0644); err != nil {
		return "", fmt.Errorf("create or Update Rules File failed with error %w", err)
	}

	return fileName, nil

}

// fileExists checks if a file exists or not
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Add eBPF map into BPFMaps list
func (b *BPF) AddBPFMap(mapName string) error {
	bpfMap, err := b.GetBPFMap(mapName)

	if err != nil {
		return err
	}

	b.BpfMaps[mapName] = *bpfMap
	return nil
}

func (b *BPF) GetBPFMap(mapName string) (*BPFMap, error) {

	if b.ProgMapCollection == nil {
		return nil, fmt.Errorf("no handle to prog map collection")
	}
	ebpfMap, ok := b.ProgMapCollection.Maps[mapName]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	ebpfInfo, err := ebpfMap.Info()
	if err != nil {
		return nil, fmt.Errorf("fetching map info failed %w", err)
	}

	tempMapID, ok := ebpfInfo.ID()
	if !ok {
		return nil, fmt.Errorf("fetching map id failed %w", err)
	}

	newBPFMap := BPFMap{
		Name:    mapName,
		MapID:   tempMapID,
		Type:    ebpfInfo.Type,
		BPFProg: b,
	}

	log.Info().Msgf("added mapID %d Name %s Type %s", newBPFMap.MapID, newBPFMap.Name, newBPFMap.Type)
	return &newBPFMap, nil
}

// Add eBPF map into BPFMaps list
func (b *BPF) AddMetricsBPFMap(mapName, aggregator string, key, samplesLength int) error {
	var tmpMetricsBPFMap MetricsBPFMap
	bpfMap, err := b.GetBPFMap(mapName)
	if err != nil {
		return fmt.Errorf("program %s metrics map %s not found : %w", b.Program.Name, mapName, err)
	}

	tmpMetricsBPFMap.BPFMap = *bpfMap
	tmpMetricsBPFMap.Key = key
	tmpMetricsBPFMap.Aggregator = aggregator
	tmpMetricsBPFMap.Values = ring.New(samplesLength)

	log.Info().Msgf("added Metrics map ID %d Name %s Type %s Key %d Aggregator %s", tmpMetricsBPFMap.MapID, tmpMetricsBPFMap.Name, tmpMetricsBPFMap.Type, tmpMetricsBPFMap.Key, tmpMetricsBPFMap.Aggregator)
	map_key := mapName + strconv.Itoa(key) + aggregator
	b.MetricsBpfMaps[map_key] = &tmpMetricsBPFMap

	return nil
}

// This method to fetch values from bpf maps and publish to metrics
func (b *BPF) MonitorMaps(ifaceName string, intervals int) error {
	for _, element := range b.Program.MonitorMaps {
		log.Debug().Msgf("monitor maps element %s key %d aggregator %s", element.Name, element.Key, element.Aggregator)
		mapKey := element.Name + strconv.Itoa(element.Key) + element.Aggregator
		_, ok := b.MetricsBpfMaps[mapKey]
		if !ok {
			if err := b.AddMetricsBPFMap(element.Name, element.Aggregator, element.Key, intervals); err != nil {
				return fmt.Errorf("not able to fetch map %s key %d aggregator %s : %w", element.Name, element.Key, element.Aggregator, err)
			}
		}
		bpfMap := b.MetricsBpfMaps[mapKey]
		MetricName := element.Name + "_" + strconv.Itoa(element.Key) + "_" + element.Aggregator
		stats.SetValue(bpfMap.GetValue(), stats.BPFMonitorMap, b.Program.Name, MetricName, ifaceName)
	}
	return nil
}

// Updating next program FD from program ID
func (b *BPF) PutNextProgFDFromID(progID int) error {
	if len(b.Program.MapName) == 0 {
		// no chaining map
		return nil
	}

	log.Info().Msgf("PutNextProgFDFromID : Map Name %s ID %d", b.Program.MapName, progID)
	ebpfMap, err := ebpf.NewMapFromID(b.ProgMapID)
	if err != nil {
		return fmt.Errorf("unable to access pinned next prog map %s %w", b.Program.MapName, err)
	}
	defer ebpfMap.Close()

	bpfProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return fmt.Errorf("failed to get next prog FD from ID for program %s %w", b.Program.Name, err)
	}
	key := 0
	fd := bpfProg.FD()
	log.Info().Msgf("PutNextProgFDFromID : Map Name %s FD %d", b.Program.MapName, fd)
	if err = ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&fd), 0); err != nil {
		return fmt.Errorf("unable to update prog next map %s %w", b.Program.MapName, err)
	}
	return nil
}

// GetProgID - This returns ID of the bpf program
func (b *BPF) GetProgID() (ebpf.ProgramID, error) {

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapNamePath, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		log.Error().Err(err).Msgf("unable to access pinned prog map %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("unable to access pinned prog map %s %w", b.PrevMapNamePath, err)
	}
	defer ebpfMap.Close()
	var value ebpf.ProgramID
	key := 0

	if err = ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		log.Warn().Err(err).Msgf("unable to look up prog map %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("unable to look up prog map %w", err)
	}

	// verify progID before storing in locally.
	_, err = ebpf.NewProgramFromID(ebpf.ProgramID(value))
	if err != nil {
		log.Warn().Err(err).Msgf("failed to verify program ID %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("failed to verify program ID %s %w", b.Program.Name, err)
	}

	log.Info().Msgf("GetProgID - Name %s PrevMapName %s ID %d", b.Program.Name, b.PrevMapNamePath, value)
	return value, nil
}

// RemoveNextProgFD Delete the entry if its last program in the chain.
// This method is called when sequence of the program changed to last in the chain
func (b *BPF) RemoveNextProgFD() error {
	if len(b.Program.MapName) == 0 {
		// no chaining map in case of root programs
		return nil
	}

	ebpfMap, err := ebpf.NewMapFromID(b.PrevProgMapID)
	if err != nil {
		return fmt.Errorf("unable to access pinned next prog map %s %w", b.Program.MapName, err)
	}
	defer ebpfMap.Close()
	key := 0

	if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
		return fmt.Errorf("failed to delete prog fd entry : %w", err)
	}
	return nil
}

// RemovePrevProgFD Delete the entry if the last element
func (b *BPF) RemovePrevProgFD() error {
	ebpfMap, err := ebpf.NewMapFromID(b.PrevProgMapID)
	if err != nil {
		return fmt.Errorf("unable to access pinned prev prog map %s %w", b.PrevMapNamePath, err)
	}
	defer ebpfMap.Close()
	key := 0

	if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
		// Some cases map may be empty ignore it.
		log.Debug().Err(err).Msg("RemovePrevProgFD failed")
	}
	return nil
}

// VerifyPinnedProgMap - making sure program fd map's pinned file is created if exists flag is true
func (b *BPF) VerifyPinnedProgMap(chain, exists bool) error {
	if !chain {
		return nil
	}
	var err error
	if len(b.Program.MapName) > 0 {
		log.Debug().Msgf("VerifyPinnedMap : Program %s MapName %s Exists %t", b.Program.Name, b.Program.MapName, exists)

		for i := 0; i < 10; i++ {
			_, err = os.Stat(b.MapNamePath)
			if err == nil && exists {
				log.Info().Msgf("VerifyPinnedProgMap creation : map file created %s", b.MapNamePath)
				return nil
			} else if err != nil && !exists {
				if _, err = os.Stat(b.MapNamePath); os.IsNotExist(err) {
					log.Info().Msgf("VerifyPinnedProgMap removal : map file removed successfully - %s ", b.MapNamePath)
					return nil
				} else if err != nil {
					log.Warn().Err(err).Msg("VerifyPinnedProgMap removal : Error checking for map file")
				} else {
					log.Warn().Msg("VerifyPinnedProgMap removal : program pinned file still exists, checking again after a second")
				}
			}
			time.Sleep(1 * time.Second)
		}

		if err != nil && exists {
			err = fmt.Errorf("VerifyPinnedProgMap creation : failed to find pinned file %s err %w", b.MapNamePath, err)
			log.Error().Err(err).Msg("")
		} else if err != nil {
			err = fmt.Errorf("VerifyPinnedProgMap removal : %s map file was never removed by BPF program %s err %w", b.MapNamePath, b.Program.Name, err)
			log.Error().Err(err).Msg("")
		}
		return err
	}

	return nil
}

// VerifyProcessObject - This method to verify cmd and process object is populated or not
func (b *BPF) VerifyProcessObject() error {

	if b.Cmd == nil {
		err := fmt.Errorf("command object is nil - %s", b.Program.Name)
		log.Error().Err(err).Msg("command object is nil -")
		return err
	}

	for i := 0; i < 10; i++ {
		if b.Cmd.Process != nil {
			return nil
		}
		log.Warn().Msgf("VerifyProcessObject: process object not found, checking again after a second")
		time.Sleep(1 * time.Second)
	}
	err := fmt.Errorf("process object is nil - %s", b.Program.Name)
	log.Error().Err(err).Msg("")
	return err
}

// VerifyMetricsMapsVanish - checks for all metrics maps references are removed from the kernel
func (b *BPF) VerifyMetricsMapsVanish() error {

	for i := 0; i < 10; i++ {
		mapExists := false
		for _, v := range b.BpfMaps {
			_, err := ebpf.NewMapFromID(v.MapID)
			if err == nil {
				log.Warn().Msgf("VerifyMetricsMapsVanish: bpf map reference still exists - %s", v.Name)
				mapExists = true
			}
		}
		if !mapExists {
			return nil
		}

		log.Warn().Msgf("VerifyMetricsMapsVanish: bpf map reference still exists - %s, checking again after a second", b.Program.Name)
		time.Sleep(1 * time.Second)
	}

	err := fmt.Errorf("metrics maps are never removed by Kernel %s", b.Program.Name)
	log.Error().Err(err).Msg("")
	return err
}

// LoadXDPAttachProgram - Load and attach xdp root program or any xdp program when chaining is disabled
func (b *BPF) LoadXDPAttachProgram(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Error().Err(err).Msgf("LoadXDPAttachProgram -look up network iface %q", ifaceName)
		return err
	}

	if err := b.LoadBPFProgram(ifaceName); err != nil {
		return err
	}
	b.XDPLink, err = link.AttachXDP(link.XDPOptions{
		Program:   b.ProgMapCollection.Programs[b.Program.EntryFunctionName],
		Interface: iface.Index,
	})

	if err != nil {
		return fmt.Errorf("could not attach xdp program %s to interface %s : %w", b.Program.Name, ifaceName, err)
	}

	// Pin the Link
	linkPinPath := fmt.Sprintf("%s/links/%s/%s_%s", b.HostConfig.BpfMapDefaultPath, ifaceName, b.Program.Name, b.Program.ProgType)
	if err := b.XDPLink.Pin(linkPinPath); err != nil {
		return err
	}
	// pin the program also
	progPinPath := fmt.Sprintf("%s/progs/%s/%s_%s", b.HostConfig.BpfMapDefaultPath, ifaceName, b.Program.EntryFunctionName, b.Program.ProgType)
	if err := b.ProgMapCollection.Programs[b.Program.EntryFunctionName].Pin(progPinPath); err != nil {
		return err
	}

	if b.HostConfig.BpfChainingEnabled {
		if err = b.UpdateProgramMap(ifaceName); err != nil {
			return err
		}
	}
	return nil
}

// UnloadProgram - Unload or detach the program from the interface and close all the program resources
func (b *BPF) UnloadProgram(ifaceName, direction string) error {
	// Verifying program attached to the interface.
	// SeqID will be 0 for root program or any other program without chaining
	if b.Program.SeqID == 0 || !b.HostConfig.BpfChainingEnabled {
		if b.Program.ProgType == models.TCType {
			if err := b.UnloadTCProgram(ifaceName, direction); err != nil {
				log.Warn().Msgf("removing tc filter failed iface %q direction %s error - %v", ifaceName, direction, err)
			}
		} else if b.Program.ProgType == models.XDPType {
			if err := b.XDPLink.Close(); err != nil {
				log.Warn().Msgf("removing xdp attached program failed iface %q direction %s error - %v", ifaceName, direction, err)
			}
		}
	}

	for _, LinkObject := range b.ProbeLinks {
		(*LinkObject).Close()
	}

	// Release all the resources of the epbf program
	if b.ProgMapCollection != nil {
		b.ProgMapCollection.Close()
	}

	// remove pinned files
	if err := b.RemovePinnedFiles(ifaceName); err != nil {
		log.Error().Err(err).Msgf("failed to remove map file for program %s => %s", ifaceName, b.Program.Name)
	}

	return nil
}

// RemovePinnedFiles - removes all the pinned files
func (b *BPF) RemovePinnedFiles(ifaceName string) error {
	if b.ProgMapCollection != nil {
		for k, v := range b.ProgMapCollection.Maps {
			var mapFilename string
			if b.Program.ProgType == models.TCType {
				mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, ifaceName, k)
			} else {
				mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, ifaceName, k)
			}
			if err := v.Unpin(); err != nil {
				return fmt.Errorf("BPF program %s prog type %s ifacename %s map %s:failed to pin the map err - %w",
					b.Program.Name, b.Program.ProgType, ifaceName, mapFilename, err)
			}
		}
	}
	// remove pinned links
	if b.XDPLink != nil {
		if err := b.XDPLink.Unpin(); err != nil {
			return fmt.Errorf("unable to unpin the xdp link for %s with err : %w", b.Program.Name, err)
		}
	}

	// remove programs pins
	if b.ProgMapCollection != nil {
		for _, v := range b.ProgMapCollection.Programs {
			if err := v.Unpin(); err != nil {
				return err
			}
		}
	}
	return nil
}

// RemoveRootProgMapFile - removes root pinned prog map file
// This is invoked if any stale map file persists for root map
func (b *BPF) RemoveRootProgMapFile(ifacename string) error {
	var mapFilename string
	switch b.Program.ProgType {
	case models.TCType:
		mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, ifacename, b.Program.MapName)
	case models.XDPType:
		mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, ifacename, b.Program.MapName)
	default:
		log.Warn().Msgf("RemoveRootProgMapFile: program %s map file %s - unknown type", b.Program.Name, b.MapNamePath)
		return fmt.Errorf("removeMapFile: program %s unknown type %s", b.Program.Name, b.Program.ProgType)
	}

	// codeQL Check
	if strings.Contains(mapFilename, "..") {
		return fmt.Errorf("%s contains relative path is not supported - %s", mapFilename, b.Program.Name)
	}

	if err := os.Remove(mapFilename); err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Msgf("RemoveRootProgMapFile: %s program type %s map file remove unsuccessfully - %s err - %#v", b.Program.ProgType, b.Program.Name, mapFilename, err)
			return fmt.Errorf("%s - remove failed with error %w", mapFilename, err)
		}
	}
	return nil
}

// VerifyCleanupMaps - This method verifies map entries in the fs is removed
func (b *BPF) VerifyCleanupMaps(chain bool) error {
	// verify pinned file is removed.
	if err := b.VerifyPinnedProgMap(chain, false); err != nil {
		log.Error().Err(err).Msgf("stop user program - failed to remove pinned file %s", b.Program.Name)
		return fmt.Errorf("stop user program - failed to remove pinned file %s : %w", b.Program.Name, err)
	}

	// Verify all metrics map references are removed from kernel
	if err := b.VerifyMetricsMapsVanish(); err != nil {
		log.Error().Err(err).Msgf("stop user program - failed to remove metric map references %s", b.Program.Name)
		return fmt.Errorf("stop user program - failed to remove metric map references %s : %w", b.Program.Name, err)
	}

	return nil
}

func ValidatePath(filePath string, destination string) (string, error) {
	destpath := filepath.Join(destination, filePath)
	if strings.Contains(filePath, "..") {
		return "", fmt.Errorf(" file contains filepath (%s) that includes (..)", filePath)
	}
	if !strings.HasPrefix(destpath, filepath.Clean(destination)+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s: illegal file path", filePath)
	}
	return destpath, nil
}

// LoadBPFProgram - This method loads the eBPF program natively.
func (b *BPF) LoadBPFProgram(ifaceName string) error {
	ObjectFile := filepath.Join(b.FilePath, b.Program.ObjectFile)
	if _, err := os.Stat(ObjectFile); os.IsNotExist(err) {
		return fmt.Errorf("%s: file doesn't exist", ObjectFile)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error().Msgf("failed to remove memory lock limits  %#v", err)
		return fmt.Errorf("%s: remove rlimit lock failed : %w", b.Program.Name, err)
	}

	objSpec, err := ebpf.LoadCollectionSpec(ObjectFile)
	if err != nil {
		return fmt.Errorf("%s: loading collection spec failed - %w", ObjectFile, err)
	}

	if err := b.CreatePinDirectories(ifaceName); err != nil {
		return err
	}

	var mapPinPath string
	if b.Program.ProgType == models.TCType {
		mapPinPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, ifaceName)
	} else if b.Program.ProgType == models.XDPType {
		mapPinPath = filepath.Join(b.HostConfig.BpfMapDefaultPath, ifaceName)
	}
	collOptions := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: mapPinPath,
		},
	}

	// Load the BPF program with the updated map options
	prg, err := ebpf.NewCollectionWithOptions(objSpec, collOptions)
	if err != nil {
		return fmt.Errorf("%s: loading of bpf program failed - %w", b.Program.Name, err)
	}

	// Persist program handle
	b.ProgMapCollection = prg

	if err := b.LoadBPFProgramProbeTypes(objSpec); err != nil {
		return fmt.Errorf("LoadBPFProgramProbeTypes failed with error %v ", err)
	}

	//var bpfProg *ebpf.Program
	if len(b.Program.EntryFunctionName) > 0 {
		bpfProg := prg.Programs[b.Program.EntryFunctionName]
		if bpfProg == nil {
			return fmt.Errorf("%s entry function is not found in the loaded object file of the program %s", b.Program.EntryFunctionName, b.Program.Name)
		}

		progInfo, err := bpfProg.Info()
		if err != nil {
			return fmt.Errorf("%s: information of bpf program failed : %w", b.Program.Name, err)
		}

		ok := false
		b.ProgID, ok = progInfo.ID()
		if !ok {
			log.Warn().Msgf("Program ID fetch failed: %s", b.Program.Name)
		}

		// Initialise metric maps
		if err := b.InitialiseMetricMaps(); err != nil {
			return fmt.Errorf("initialising metric maps failed %w", err)
		}

		if err := b.PinBpfMaps(ifaceName); err != nil {
			return err
		}
	}
	return nil
}

// InitialiseMetricMaps - This method initialises all the monitor maps
func (b *BPF) InitialiseMetricMaps() error {
	if b.ProgMapCollection == nil {
		log.Warn().Msgf("prog is not loaded by l3afd")
		return nil
	}
	for _, tmpMap := range b.Program.MonitorMaps {
		tmpMetricsMap := b.ProgMapCollection.Maps[tmpMap.Name]
		if tmpMetricsMap == nil {
			log.Error().Msgf("%s map is not loaded", tmpMap.Name)
			continue
		}

		var err error
		log.Debug().Msgf("Program - %s map name %s key size %d value size %d\n", b.Program.Name, tmpMap.Name, tmpMetricsMap.KeySize(), tmpMetricsMap.ValueSize())
		if tmpMetricsMap.KeySize() == 1 {
			var k int8
			switch tmpMetricsMap.ValueSize() {
			case 1:
				var v int8
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 2:
				var v int16
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 4:
				var v int32
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 8:
				var v int64
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			default:
				log.Error().Msgf("unsupported key type int8 and value size - %d", tmpMetricsMap.ValueSize())
			}
		} else if tmpMetricsMap.KeySize() == 2 {
			var k int16
			switch tmpMetricsMap.ValueSize() {
			case 1:
				var v int8
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 2:
				var v int16
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 4:
				var v int32
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 8:
				var v int64
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			default:
				log.Error().Msgf("unsupported map key type int16 and value size - %d", tmpMetricsMap.ValueSize())
			}
		} else if tmpMetricsMap.KeySize() == 4 {
			var k int32
			switch tmpMetricsMap.ValueSize() {
			case 1:
				var v int8
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 2:
				var v int16
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 4:
				var v int32
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 8:
				var v int64
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			default:
				log.Error().Msgf("unsupported map key type int32 and value size - %d", tmpMetricsMap.ValueSize())
			}
		} else if tmpMetricsMap.KeySize() == 8 {
			var k int64
			switch tmpMetricsMap.ValueSize() {
			case 1:
				var v int8
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 2:
				var v int16
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 4:
				var v int32
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			case 8:
				var v int64
				err = tmpMetricsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&v), 0)
			default:
				log.Error().Msgf("unsupported key type int64 and value size - %d", tmpMetricsMap.ValueSize())
			}
		}
		if err != nil {
			return fmt.Errorf("update hash map element failed for map name %s error %v", tmpMap.Name, err)
		}
	}
	return nil
}

// IsLoaded - Method verifies whether bpf program is loaded or not
// Here it checks whether prog ID is valid and active
func (b *BPF) IsLoaded() bool {
	if b.ProgID == 0 {
		return true
	}
	ebpfProg, err := ebpf.NewProgramFromID(b.ProgID)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		log.Debug().Msgf("IsLoaded - %s is not loaded or invalid program id %d", b.Program.Name, uint32(b.ProgID))
		return false
	}
	defer ebpfProg.Close()
	return true
}

func (b *BPF) StartUserProgram(ifaceName, direction string, chain bool) error {
	cmd := filepath.Join(b.FilePath, b.Program.CmdStart)
	// Validate
	if err := AssertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %w", b.Program.CmdStart, err)
	}

	args := make([]string, 0, len(b.Program.StartArgs)<<1)
	if len(ifaceName) > 0 {
		args = append(args, "--iface="+ifaceName) // attaching to interface
	}
	if len(direction) > 0 {
		args = append(args, "--direction="+direction) // direction xdpingress or ingress or egress
	}

	if chain && b.ProgMapCollection == nil {
		// chaining from user program
		if len(b.PrevMapNamePath) > 1 {
			args = append(args, "--map-name="+b.PrevMapNamePath)
		}
	}

	if len(b.HostConfig.BPFLogDir) > 1 {
		args = append(args, "--log-dir="+b.HostConfig.BPFLogDir)
	}

	if len(b.Program.RulesFile) > 1 && len(b.Program.Rules) > 1 {
		fileName, err := b.createUpdateRulesFile(direction)
		if err == nil {
			args = append(args, "--rules-file="+fileName)
		}
	}

	for k, val := range b.Program.StartArgs {
		if v, ok := val.(string); !ok {
			err := fmt.Errorf("start args is not a string for the bpf program %s", b.Program.Name)
			log.Error().Err(err).Msgf("failed to convert start args value into string for program %s", b.Program.Name)
			return err
		} else {
			args = append(args, "--"+k+"="+v)
		}
	}

	log.Info().Msgf("BPF Program start command : %s %v", cmd, args)
	b.Cmd = execCommand(cmd, args...)
	if err := b.Cmd.Start(); err != nil {
		log.Info().Err(err).Msgf("user program failed - %s", b.Program.Name)
		return fmt.Errorf("failed to start : %s %v with err: %w", cmd, args, err)
	}
	if !b.Program.UserProgramDaemon {
		log.Info().Msgf("no user program - %s No Pid", b.Program.Name)
		if err := b.Cmd.Wait(); err != nil {
			log.Warn().Msgf("failed at wait - %s err %s", b.Program.Name, err.Error())
		}
		b.Cmd = nil
	} else {
		if err := b.SetPrLimits(); err != nil {
			log.Warn().Err(err).Msg("failed to set resource limits")
		}
		log.Info().Msgf("BPF program - %s User program Process id %d started", b.Program.Name, b.Cmd.Process.Pid)
	}

	return nil
}

// CreatePinDirectories - This method creates directory for ebpf objects
// TC maps are pinned to directory /sys/fs/bpf/tc/globals/<ifaceName>
// XDP maps are pinned to directory /sys/fs/bpf/<ifaceName>
// links are pinned to directory /sys/fs/bpf/links/<ifaceName>
// Program are pinned to directory  /sys/fs/bpf/progs/<ifaceName>
func (b *BPF) CreatePinDirectories(ifaceName string) error {
	var mapPathDir string
	if b.Program.ProgType == models.XDPType {
		mapPathDir = filepath.Join(b.HostConfig.BpfMapDefaultPath, ifaceName)
	} else if b.Program.ProgType == models.TCType {
		mapPathDir = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, ifaceName)
	}
	// Create map dir for XDP and TC programs only
	if len(mapPathDir) > 0 {
		// codeQL Check
		if strings.Contains(mapPathDir, "..") {
			return fmt.Errorf("%s contains relative path is not supported - %s", mapPathDir, b.Program.Name)
		}
		if err := os.MkdirAll(mapPathDir, 0750); err != nil {
			return fmt.Errorf("%s failed to create map dir path of %s program %s with err : %w", mapPathDir, b.Program.ProgType, b.Program.Name, err)
		}
	}

	linksPathDir := filepath.Join(b.HostConfig.BpfMapDefaultPath, "links", ifaceName)
	if strings.Contains(linksPathDir, "..") {
		return fmt.Errorf("%s contains relative path is not supported - %s", linksPathDir, b.Program.Name)
	}
	if err := os.MkdirAll(linksPathDir, 0750); err != nil {
		return fmt.Errorf("%s failed to create map dir path of %s program %s with err : %w", linksPathDir, b.Program.ProgType, b.Program.Name, err)
	}

	ProgPathDir := filepath.Join(b.HostConfig.BpfMapDefaultPath, "progs", ifaceName)
	if strings.Contains(ProgPathDir, "..") {
		return fmt.Errorf("%s contains relative path is not supported - %s", ProgPathDir, b.Program.Name)
	}
	if err := os.MkdirAll(ProgPathDir, 0750); err != nil {
		return fmt.Errorf("%s failed to create map dir path of %s program %s with err : %w", ProgPathDir, b.Program.ProgType, b.Program.Name, err)
	}
	return nil
}

// AttachBPFProgram - method to attach bpf program to interface
func (b *BPF) AttachBPFProgram(ifaceName, direction string) error {
	if b.Program.ProgType == models.XDPType {
		if err := b.LoadXDPAttachProgram(ifaceName); err != nil {
			return fmt.Errorf("failed to attach xdp program %s to inferface %s with err: %w", b.Program.Name, ifaceName, err)
		}
	} else if b.Program.ProgType == models.TCType {
		if err := b.LoadTCAttachProgram(ifaceName, direction); err != nil {
			return fmt.Errorf("failed to attach tc program %s to inferface %s direction %s with err: %w", b.Program.Name, ifaceName, direction, err)
		}
	}
	return nil
}

// PinBpfMaps - Pinning tc and xdp maps
func (b *BPF) PinBpfMaps(ifaceName string) error {
	// create map path directory
	// if err := b.CreatePinDirectories(ifaceName); err != nil {
	// 	return err
	// }

	for k, v := range b.ProgMapCollection.Maps {
		var mapFilename string
		if b.Program.ProgType == models.TCType {
			mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, models.TCMapPinPath, ifaceName, k)
		} else {
			mapFilename = filepath.Join(b.HostConfig.BpfMapDefaultPath, ifaceName, k)
		}
		// In case one of the program pins the map then other program will skip
		if !fileExists(mapFilename) {
			if err := v.Pin(mapFilename); err != nil {
				return fmt.Errorf("eBPF program %s map %s:failed to pin the map err - %w", b.Program.Name, mapFilename, err)
			}
		}
	}
	return nil
}

// UpdateProgramMap - Store the program map reference
func (b *BPF) UpdateProgramMap(ifaceName string) error {
	// Verify chaining map is provided
	if len(b.Program.MapName) == 0 {
		return fmt.Errorf("program map name is missing for %s program %s", b.Program.ProgType, b.Program.Name)
	}

	bpfRootMap := b.ProgMapCollection.Maps[b.Program.MapName]

	ebpfInfo, err := bpfRootMap.Info()
	if err != nil {
		return fmt.Errorf("fetching map info failed for %s program %s to interface %s : %w", b.Program.ProgType, b.Program.Name, ifaceName, err)
	}

	var ok bool
	b.ProgMapID, ok = ebpfInfo.ID()
	if !ok {
		return fmt.Errorf("fetching map id failed for %s program %s to interface %s : %w", b.Program.ProgType, b.Program.Name, ifaceName, err)
	}

	return nil
}

// LoadBPFProgramChain - Load the BPF program and chain it.
func (b *BPF) LoadBPFProgramChain(ifaceName, direction string) error {

	if err := b.LoadBPFProgram(ifaceName); err != nil {
		return err
	}

	// pin the program also
	progPinPath := fmt.Sprintf("%s/progs/%s/%s_%s", b.HostConfig.BpfMapDefaultPath, ifaceName, b.Program.EntryFunctionName, b.Program.ProgType)
	if err := b.ProgMapCollection.Programs[b.Program.EntryFunctionName].Pin(progPinPath); err != nil {
		return err
	}

	// Update program map id
	if err := b.UpdateProgramMap(ifaceName); err != nil {
		return err
	}

	// Link this program into previous program map
	ebpfMap, err := ebpf.NewMapFromID(b.PrevProgMapID)
	if err != nil {
		return fmt.Errorf("unable to access pinned previous prog map %s %w", b.PrevMapNamePath, err)
	}
	defer ebpfMap.Close()

	bpfProg := b.ProgMapCollection.Programs[b.Program.EntryFunctionName]
	if bpfProg == nil {
		return fmt.Errorf("%s entry function is not found in the loaded object file of the program %s", b.Program.EntryFunctionName, b.Program.Name)
	}

	key := 0
	fd := bpfProg.FD()
	log.Info().Msgf("previous program map path %s FD %d", b.PrevMapNamePath, fd)
	if err = ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&fd), 0); err != nil {
		return fmt.Errorf("unable to update prog next map %s %v", b.Program.MapName, err)
	}
	log.Info().Msgf("eBPF program %s loaded on interface %s direction %s successfully", b.Program.Name, ifaceName, direction)
	return nil
}

func ReturnFirstFifteenOrLessChars(s string) string {
	if len(s) > 15 {
		return s[:15]
	}
	return s
}
