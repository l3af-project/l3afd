// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package nf provides primitives for BPF programs / Network Functions.
package kf

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"container/ring"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"tbd/admind/models"
	"tbd/cfgdist/kvstores/emitter"
	"tbd/go-shared/nsqbatch"
	"tbd/sys/unix"

	"tbd/l3afd/config"
	"tbd/l3afd/stats"

	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"
	"github.com/rs/zerolog/log"
)

var (
	execCommand           = exec.Command
	copyBufPool sync.Pool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}
)

const executePerm uint32 = 0111
const bpfStatus string = "RUNNING"

// BPF defines run time details for BPFProgram.
type BPF struct {
	Program        models.BPFProgram
	Cmd            *exec.Cmd
	FilePath       string                    // Binary file path
	RestartCount   int                       // To track restart count
	LogDir         string                    // Log dir for the BPF program
	PrevMapName    string                    // Map name to link
	ProgID         int                       // eBPF Program ID
	BpfMaps        map[string]BPFMap         // Config maps passed as map-args, Map name is Key
	MetricsBpfMaps map[string]*MetricsBPFMap // Metrics map name+key+aggregator is key
	Ctx            context.Context
	Done           chan bool
	DataCenter     string
}

func NewBpfProgram(ctx context.Context, program models.BPFProgram, logDir, dataCenter string) *BPF {
	bpf := &BPF{
		Program:        program,
		RestartCount:   0,
		Cmd:            nil,
		FilePath:       "",
		LogDir:         logDir,
		BpfMaps:        make(map[string]BPFMap, 0),
		MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
		Ctx:            ctx,
		Done:           nil,
		DataCenter:     dataCenter,
	}
	return bpf
}

// Loading the Root Program for a given interface.
func LoadRootProgram(ifaceName string, direction string, eBPFType string, conf *config.Config) (*BPF, error) {

	log.Info().Msgf("LoadRootProgram iface %s direction %s ebpfType %s", ifaceName, direction, eBPFType)
	var rootProgBPF *BPF

	switch eBPFType {
	case models.XDPType:
		rootProgBPF = &BPF{
			Program: models.BPFProgram{
				Name:          conf.XDPRootProgramName,
				Artifact:      conf.XDPRootProgramArtifact,
				MapName:       conf.XDPRootProgramMapName,
				Version:       conf.XDPRootProgramVersion,
				IsUserProgram: conf.XDPRootProgramIsUserProgram,
				CmdStart:      conf.XDPRootProgramCommand,
				CmdStop:       conf.XDPRootProgramCommand,
				CmdStatus:     "",
				AdminStatus:   models.Enabled,
				SeqID:         0,
			},
			RestartCount: 0,
			Cmd:          nil,
			FilePath:     "",
			LogDir:       "",
			PrevMapName:  "",
		}
	case models.TCType:
		rootProgBPF = &BPF{
			Program: models.BPFProgram{
				Name:          conf.TCRootProgramName,
				Artifact:      conf.TCRootProgramArtifact,
				Version:       conf.TCRootProgramVersion,
				IsUserProgram: conf.TCRootProgramIsUserProgram,
				CmdStart:      conf.TCRootProgramCommand,
				CmdStop:       conf.TCRootProgramCommand,
				CmdStatus:     "",
				AdminStatus:   models.Enabled,
			},
			RestartCount: 0,
			Cmd:          nil,
			FilePath:     "",
			LogDir:       "",
			PrevMapName:  "",
		}
		if direction == models.IngressType {
			rootProgBPF.Program.MapName = conf.TCRootProgramIngressMapName
		} else if direction == models.EgressType {
			rootProgBPF.Program.MapName = conf.TCRootProgramEgressMapName
		}
	default:
		return nil, fmt.Errorf("unknown direction %s for root program in iface %s", direction, ifaceName)
	}

	// Loading default arguments
	rootProgBPF.Program.AddStartArgs(models.L3afDNFArgs{Key: "cmd", Value: models.StartType})
	rootProgBPF.Program.AddStopArgs(models.L3afDNFArgs{Key: "cmd", Value: models.StopType})

	if err := rootProgBPF.VerifyAndGetArtifacts(conf); err != nil {
		log.Error().Err(err).Msg("failed to get root artifacts")
		return nil, err
	}

	// On l3afd crashing scenario verify root program are unloaded properly by checking existence of persisted maps
	// if map file exists then root program is still running
	if fileExists(rootProgBPF.Program.MapName) {
		log.Warn().Msgf("previous instance of root program %s is running, stopping it ", rootProgBPF.Program.Name)
		if err := rootProgBPF.Stop(ifaceName, direction, conf.BpfChainingEnabled); err != nil {
			return nil, fmt.Errorf("failed to stop root program on iface %s name %s direction %s", ifaceName, rootProgBPF.Program.Name, direction)
		}
	}

	if err := rootProgBPF.Start(ifaceName, direction, conf.BpfChainingEnabled); err != nil {
		return nil, fmt.Errorf("failed to start root program on interface %s", ifaceName)
	}

	return rootProgBPF, nil
}

// This method get the Linux distribution Codename. This logic works on ubuntu
// Here assumption is all edge nodes are running with lsb modules.
// It returns empty string in case of error
func LinuxDistribution() (string, error) {

	linuxDistrib := execCommand("lsb_release", "-cs")
	var out bytes.Buffer
	linuxDistrib.Stdout = &out

	if err := linuxDistrib.Run(); err != nil {
		return "", fmt.Errorf("l3afd/nf : Failed to run command with error: %w", err)
	}

	return strings.TrimSpace(string(out.Bytes())), nil
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
		return fmt.Errorf("failed to fetch processes list")
	}
	log.Info().Msgf("Searching for process %s and not ppid %d", processName, myPid)
	for _, process := range processList {
		if strings.Contains(process.Executable(), psName) {
			if process.PPid() != myPid {
				log.Warn().Msgf("found process id %d name %s ppid %d, stopping it", process.Pid(), process.Executable(), process.PPid())
				err := syscall.Kill(process.Pid(), syscall.SIGTERM)
				if err != nil {
					return fmt.Errorf("external BPFProgram stop failed with error: %w", err)
				}
			}
		}
	}
	return nil
}

// Stop returns the last error seen, but stops bpf program.
// Clean up all map handles.
// Verify next program pinned map file is removed
func (b *BPF) Stop(ifaceName, direction string, chain bool) error {
	if b.Program.IsUserProgram && b.Cmd == nil {
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

	// Stop KFcnfigs
	if len(b.Program.CmdConfig) > 0 && len(b.Program.ConfigFilePath) > 0 {
		log.Info().Msgf("Stopping KF configs %s ", b.Program.Name)
		b.Done <- true
	}

	// Reset ProgID
	b.ProgID = 0

	stats.Incr(stats.NFStopCount, b.Program.Name, direction)

	// Setting NFRunning to 0, indicates not running
	stats.Set(0.0, stats.NFRunning, b.Program.Name, direction)

	if len(b.Program.CmdStop) < 1 {
		if err := syscall.Kill(b.Cmd.Process.Pid, syscall.SIGTERM); err != nil {
			return fmt.Errorf("BPFProgram %s syscall.SIGTERM failed with error: %w", b.Program.Name, err)
		}
		if b.Cmd != nil {
			if err := b.Cmd.Wait(); err != nil {
				log.Error().Err(err).Msgf("cmd wait at stopping bpf program %s errored", b.Program.Name)
			}
			b.Cmd = nil
		}

		// verify pinned map file is removed.
		if err := b.VerifyPinnedMapVanish(chain); err != nil {
			log.Error().Err(err).Msgf("stop user program - failed to remove pinned file %s", b.Program.Name)
			return fmt.Errorf("stop user program - failed to remove pinned file %s", b.Program.Name)
		}
		return nil
	}

	cmd := filepath.Join(b.FilePath, b.Program.CmdStop)

	if err := assertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %w", b.Program.CmdStop, err)
	}

	args := make([]string, 0, len(b.Program.StopArgs)<<1)
	args = append(args, "--iface="+ifaceName)     // detaching from iface
	args = append(args, "--direction="+direction) // xdpingress or ingress or egress

	for _, val := range b.Program.StopArgs {
		args = append(args, "--"+val.Key+"="+val.Value)
	}

	log.Info().Msgf("bpf program stop command : %s %v", cmd, args)
	prog := execCommand(cmd, args...)
	if err := prog.Run(); err != nil {
		log.Warn().Err(err).Msgf("l3afd/nf : Failed to stop the program %s", b.Program.CmdStop)
	}
	b.Cmd = nil

	// verify pinned map file is removed.
	if err := b.VerifyPinnedMapVanish(chain); err != nil {
		log.Error().Err(err).Msgf("failed to remove pinned file %s", b.Program.Name)
		return fmt.Errorf("failed to remove pinned file %s", b.Program.Name)
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

	if err := StopExternalRunningProcess(b.Program.CmdStart); err != nil {
		return fmt.Errorf("failed to stop external instance of the program %s with error : %w", b.Program.CmdStart, err)
	}

	cmd := filepath.Join(b.FilePath, b.Program.CmdStart)
	// Validate
	if err := assertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %w", b.Program.CmdStart, err)
	}

	// Making sure old map entry is removed before passing the prog fd map to the program.
	if len(b.PrevMapName) > 0 {
		if err := b.RemovePrevProgFD(); err != nil {
			log.Error().Err(err).Msgf("ProgramMap %s entry removal failed", b.PrevMapName)
		}
	}

	args := make([]string, 0, len(b.Program.StartArgs)<<1)
	args = append(args, "--iface="+ifaceName)     // attaching to interface
	args = append(args, "--direction="+direction) // direction xdpingress or ingress or egress

	if chain {
		if len(b.PrevMapName) > 1 {
			args = append(args, "--map-name="+b.PrevMapName)
		}
	}

	if len(b.LogDir) > 1 {
		args = append(args, "--log-dir="+b.LogDir)
	}

	if len(b.Program.RulesFile) > 1 && len(b.Program.Rules) > 1 {
		fileName, err := b.createUpdateRulesFile(direction)
		if err == nil {
			args = append(args, "--rules-file="+fileName)
		}
	}

	for _, val := range b.Program.StartArgs {
		args = append(args, "--"+val.Key+"="+val.Value)
	}

	log.Info().Msgf("BPF Program start command : %s %v", cmd, args)
	b.Cmd = execCommand(cmd, args...)
	if err := b.Cmd.Start(); err != nil {
		log.Info().Err(err).Msgf("user mode BPF program failed - %s", b.Program.Name)
		return fmt.Errorf("failed to start : %s %v", cmd, args)
	}
	if !b.Program.IsUserProgram {
		log.Info().Msgf("no user mode BPF program - %s No Pid", b.Program.Name)
		if err := b.Cmd.Wait(); err != nil {
			return fmt.Errorf("cmd wait at starting of bpf program returned with error %w", err)
		}
		b.Cmd = nil

		if err := b.VerifyPinnedMapExists(chain); err != nil {
			return fmt.Errorf("no userprogram and failed to find pinned file %s, %w", b.Program.MapName, err)
		}
		return nil
	}

	isRunning, err := b.isRunning()
	if isRunning == false {
		log.Error().Err(err).Msg("eBPF program failed to start")
		return fmt.Errorf("bpf program %s failed to start %w", b.Program.Name, err)
	}

	// making sure program fd map pinned file is created
	if err := b.VerifyPinnedMapExists(chain); err != nil {
		return fmt.Errorf("failed to find pinned file %s  %w", b.Program.MapName, err)
	}

	if len(b.Program.MapArgs) > 0 {
		if err := b.Update(ifaceName, direction); err != nil {
			log.Error().Err(err).Msg("failed to update network functions BPF maps")
			return fmt.Errorf("failed to update network functions BPF maps %w", err)
		}
	}

	// Fetch when prev program map is updated
	if len(b.PrevMapName) > 0 {
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
			log.Error().Err(err).Msg("failed to fetch network functions program FD")
			return fmt.Errorf("failed to fetch network functions program FD %w", err)
		}
	}

	// KFconfigs
	if len(b.Program.CmdConfig) > 0 && len(b.Program.ConfigFilePath) > 0 {
		log.Info().Msgf("KP specific config monitoring - %s", b.Program.ConfigFilePath)
		b.Done = make(chan bool)
		go b.RunKFConfigs()
	}

	if err := b.SetPrLimits(); err != nil {
		log.Warn().Err(err).Msg("failed to set resource limits")
	}
	stats.Incr(stats.NFStartCount, b.Program.Name, direction)
	stats.Set(float64(time.Now().Unix()), stats.NFStartTime, b.Program.Name, direction)

	log.Info().Msgf("BPF program - %s started Process id %d Program ID %d", b.Program.Name, b.Cmd.Process.Pid, b.ProgID)
	return nil
}

// Updates the config map_args
func (b *BPF) Update(ifaceName, direction string) error {
	for _, val := range b.Program.MapArgs {
		log.Info().Msgf("Update map args key %s val %s", val.Key, val.Value)
		// fetch the key in
		bpfMap, ok := b.BpfMaps[val.Key]
		if !ok {
			if err := b.AddBPFMap(val.Key); err != nil {
				return err
			}
			bpfMap, _ = b.BpfMaps[val.Key]
		}

		bpfMap.Update(val.Value)
	}
	stats.Incr(stats.NFUpdateCount, b.Program.Name, direction)
	return nil
}

// Status of user program is running
func (b *BPF) isRunning() (bool, error) {
	// No user program or may be disabled
	if !b.Program.IsUserProgram && len(b.Program.CmdStatus) > 1 {
		cmd := filepath.Join(b.FilePath, b.Program.CmdStatus)

		if err := assertExecutable(cmd); err != nil {
			return false, fmt.Errorf("Failed to execute %s with error: %w", b.Program.CmdStatus, err)
		}

		args := make([]string, 0, len(b.Program.StatusArgs)<<1)

		for _, val := range b.Program.StatusArgs {
			args = append(args, "--"+val.Key)
			if len(val.Value) > 0 {
				args = append(args, "="+val.Value)
			}
		}

		prog := execCommand(cmd, args...)
		var out bytes.Buffer
		prog.Stdout = &out
		prog.Stderr = &out
		if err := prog.Run(); err != nil {
			log.Warn().Err(err).Msgf("l3afd/nf : Failed to execute %s", b.Program.CmdStatus)
		}

		outStr, errStr := string(out.Bytes()), string(out.Bytes())
		if strings.EqualFold(outStr, bpfStatus) {
			return true, nil
		}

		return false, fmt.Errorf("l3afd/nf : BPF Program not running %s", errStr)
	}

	if err := b.VerifyProcessObject(); err != nil {
		return false, errors.New("No process id found")
	}

	procState, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", b.Cmd.Process.Pid))
	if err != nil {
		return false, fmt.Errorf("BPF Program not running %s because of error: %w", b.Program.Name, err)
	}
	var u1, u2, state string
	_, err = fmt.Sscanf(string(procState), "%s %s %s", &u1, &u2, &state)
	if err != nil {
		return false, fmt.Errorf("Failed to scan proc state with error: %w", err)
	}
	if state == "Z" {
		return false, fmt.Errorf("Process %d in Zombie state", b.Cmd.Process.Pid)
	}

	return true, nil
}

// Set process resource limits only non-zero value
func (b *BPF) SetPrLimits() error {
	var rlimit unix.Rlimit

	if b.Cmd == nil {
		return errors.New("No Process to set limits")
	}

	if b.Program.Memory != 0 {
		rlimit.Cur = uint64(b.Program.Memory)
		rlimit.Max = uint64(b.Program.Memory)

		if err := prLimit(b.Cmd.Process.Pid, unix.RLIMIT_AS, &rlimit); err != nil {
			log.Error().Err(err).Msgf("Failed to set Memory limits - %s", b.Program.Name)
		}
	}

	if b.Program.CPU != 0 {
		rlimit.Cur = uint64(b.Program.CPU)
		rlimit.Max = uint64(b.Program.CPU)
		if err := prLimit(b.Cmd.Process.Pid, unix.RLIMIT_CPU, &rlimit); err != nil {
			log.Error().Err(err).Msgf("Failed to set CPU limits - %s", b.Program.Name)
		}
	}

	return nil
}

// Check binary already exists
func (b *BPF) VerifyAndGetArtifacts(conf *config.Config) error {

	fPath := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version, strings.Split(b.Program.Artifact, ".")[0])
	if _, err := os.Stat(fPath); os.IsNotExist(err) {
		return b.GetArtifacts(conf)
	}

	b.FilePath = fPath
	return nil
}

// GetArtifacts downloads artifacts from the nexus repo
func (b *BPF) GetArtifacts(conf *config.Config) error {
	var fPath = ""

	proximityURL, err := url.Parse(conf.ProximityUrl)
	if err != nil {
		return fmt.Errorf("unknown proximity url format: %w", err)
	}

	linuxDist, err := LinuxDistribution()
	if err != nil {
		return fmt.Errorf("failed to find proximity download path: %w", err)
	}

	proximityURL.Path = path.Join(proximityURL.Path, b.Program.Name, b.Program.Version, linuxDist, b.Program.Artifact)
	log.Info().Msgf("Downloading - %s", proximityURL)

	timeOut := time.Duration(conf.HttpClientTimeout) * time.Second
	var netTransport = &http.Transport{
		ResponseHeaderTimeout: timeOut,
	}
	client := http.Client{Transport: netTransport, Timeout: timeOut}

	// Get the data
	resp, err := client.Get(proximityURL.String())
	if err != nil {
		return fmt.Errorf("Download failed: %w", err)
	}
	defer resp.Body.Close()

	buf := &bytes.Buffer{}
	buf.ReadFrom(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Get request returned unexpected status code: %d (%s), %d was expected\n\tResponse Body: %s\n", resp.StatusCode, http.StatusText(resp.StatusCode), http.StatusOK, buf.Bytes())
	}

	archive, err := gzip.NewReader(buf)
	if err != nil {
		return fmt.Errorf("Failed to create Gzip reader: %w", err)
	}
	defer archive.Close()

	tarReader := tar.NewReader(archive)
	tempDir := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("Untar failed: %w", err)
		}
		fPath = filepath.Join(tempDir, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(fPath, info.Mode()); err != nil {
				return fmt.Errorf("Untar failed to create directories: %w", err)
			}
			continue
		}

		file, err := os.OpenFile(fPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return fmt.Errorf("Untar failed to create file: %w", err)
		}
		defer file.Close()

		buf := copyBufPool.Get().([]byte)
		_, err = io.CopyBuffer(file, tarReader, buf)
		if err != nil {
			return fmt.Errorf("GetArtifacts failed to copy files: %w", err)
		}
		copyBufPool.Put(buf)
	}

	newDir := strings.Split(b.Program.Artifact, ".")
	b.FilePath = filepath.Join(tempDir, newDir[0])

	return nil
}

// prLimit set the memory and cpu limits for the bpf program
func prLimit(pid int, limit uintptr, rlimit *unix.Rlimit) error {
	_, _, errno := unix.RawSyscall6(unix.SYS_PRLIMIT64,
		uintptr(pid),
		limit,
		uintptr(unsafe.Pointer(rlimit)),
		0, 0, 0)

	if errno != 0 {
		log.Error().Msgf("Failed to set prlimit for process %d and errorno %d", pid, errno)
		return errors.New("Failed to set prlimit")
	}

	return nil
}

// assertExecutable checks for executable permissions
func assertExecutable(fPath string) error {
	info, err := os.Stat(fPath)
	if err != nil {
		return fmt.Errorf("Could not stat file: %s with error: %w", fPath, err)
	}
	if (info.Mode()&os.ModePerm)&os.FileMode(executePerm) == 0 {
		return fmt.Errorf("File: %s, is not executable.", fPath)
	}
	return nil
}

// create rules file
func (b *BPF) createUpdateRulesFile(direction string) (string, error) {

	if len(b.Program.RulesFile) < 1 {
		return "", fmt.Errorf("RulesFile name is empty")
	}

	fileName := path.Join(b.FilePath, direction, b.Program.RulesFile)

	if err := ioutil.WriteFile(fileName, []byte(b.Program.Rules), 0644); err != nil {
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
	var newBPFMap BPFMap

	// TC maps are pinned by default
	if b.Program.EBPFType == models.TCType {
		ebpfMap, err := ebpf.LoadPinnedMap(mapName, nil)
		if err != nil {
			return nil, fmt.Errorf("ebpf LoadPinnedMap failed %v", err)
		}
		defer ebpfMap.Close()

		ebpfInfo, err := ebpfMap.Info()
		if err != nil {
			return nil, fmt.Errorf("fetching map info failed %v", err)
		}

		tempMapID, ok := ebpfInfo.ID()
		if !ok {
			return nil, fmt.Errorf("fetching map id failed %v", err)
		}

		newBPFMap = BPFMap{
			Name:  ebpfInfo.Name,
			MapID: tempMapID,
			Type:  ebpfInfo.Type,
		}

	} else if b.Program.EBPFType == models.XDPType {

		// XDP maps
		// map names are truncated to 15 chars
		mpName := mapName
		if len(mapName) > 15 {
			mpName = mapName[:15]
		}
		var mpId ebpf.MapID = 0

		for {
			tmpMapId, err := ebpf.MapGetNextID(mpId)

			if err != nil {
				return nil, fmt.Errorf("failed to fetch the map object %v", err)
			}

			ebpfMap, err := ebpf.NewMapFromID(tmpMapId)
			if err != nil {
				return nil, fmt.Errorf("failed to get NewMapFromID %v", err)
			}
			defer ebpfMap.Close()

			ebpfInfo, err := ebpfMap.Info()
			if err != nil {
				return nil, fmt.Errorf("failed to fetch ebpfinfo %v", err)
			}

			if ebpfInfo.Name == mpName {
				newBPFMap = BPFMap{
					Name:  ebpfInfo.Name,
					MapID: tmpMapId,
					Type:  ebpfInfo.Type,
				}
				break
			}
			mpId = tmpMapId
		}
	}

	log.Info().Msgf("added mapID %d Name %s Type %s", newBPFMap.MapID, newBPFMap.Name, newBPFMap.Type)
	return &newBPFMap, nil
}

// Add eBPF map into BPFMaps list
func (b *BPF) AddMetricsBPFMap(mapName, aggregator string, key, samplesLength int) error {

	var tmpMetricsBPFMap MetricsBPFMap
	bpfMap, err := b.GetBPFMap(mapName)

	if err != nil {
		return err
	}

	tmpMetricsBPFMap.BPFMap = *bpfMap
	tmpMetricsBPFMap.key = key
	tmpMetricsBPFMap.aggregator = aggregator
	tmpMetricsBPFMap.Values = ring.New(samplesLength)

	log.Info().Msgf("added Metrics map ID %d Name %s Type %s Key %d Aggregator %s", tmpMetricsBPFMap.MapID, tmpMetricsBPFMap.Name, tmpMetricsBPFMap.Type, tmpMetricsBPFMap.key, tmpMetricsBPFMap.aggregator)
	map_key := mapName + strconv.Itoa(key) + aggregator
	b.MetricsBpfMaps[map_key] = &tmpMetricsBPFMap

	return nil
}

// This method to fetch values from bpf maps and publish to metrics
func (b *BPF) MonitorMaps(ifaceName string, intervals int) error {
	for _, element := range b.Program.MonitorMaps {
		log.Debug().Msgf("monitor maps element %s ", element.Name)
		mapKey := element.Name + strconv.Itoa(element.Key) + element.Aggregator
		bpfMap, ok := b.MetricsBpfMaps[mapKey]
		if !ok {
			if err := b.AddMetricsBPFMap(element.Name, element.Aggregator, element.Key, intervals); err != nil {
				return fmt.Errorf("not able to fetch map %s key %d aggregator %s", element.Name, element.Key, element.Aggregator)
			}
		}
		bpfMap, _ = b.MetricsBpfMaps[mapKey]
		MetricName := element.Name + "_" + strconv.Itoa(element.Key) + "_" + element.Aggregator
		stats.SetValue(bpfMap.GetValue(), stats.NFMointorMap, b.Program.Name, MetricName)
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
	ebpfMap, err := ebpf.LoadPinnedMap(b.Program.MapName, nil)
	if err != nil {
		return fmt.Errorf("unable to access pinned next prog map %s %v", b.Program.MapName, err)
	}
	defer ebpfMap.Close()

	bpfProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return fmt.Errorf("failed to get next prog FD from ID for program %s %v", b.Program.Name, err)
	}
	key := 0
	fd := bpfProg.FD()
	log.Info().Msgf("PutNextProgFDFromID : Map Name %s FD %d", b.Program.MapName, fd)
	if err = ebpfMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&fd), 0); err != nil {
		return fmt.Errorf("unable to update prog next map %s %v", b.Program.MapName, err)
	}
	return nil
}

// GetProgID - This returns ID of the bpf program
func (b *BPF) GetProgID() (int, error) {

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapName, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		log.Error().Err(err).Msgf("unable to access pinned prog map %s", b.PrevMapName)
		return 0, fmt.Errorf("unable to access pinned prog map %s %v", b.PrevMapName, err)
	}
	defer ebpfMap.Close()
	var value int
	key := 0

	if err = ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		log.Warn().Err(err).Msgf("unable to lookup prog map %s", b.PrevMapName)
		return 0, fmt.Errorf("unable to lookup prog map %w", err)
	}

	// verify progID before storing in locally.
	_, err = ebpf.NewProgramFromID(ebpf.ProgramID(value))
	if err != nil {
		log.Warn().Err(err).Msgf("failed to verify program ID %s", b.PrevMapName)
		return 0, fmt.Errorf("failed to verify program ID %s %v", b.Program.Name, err)
	}

	log.Info().Msgf("GetProgID - Name %s PrevMapName %s ID %d", b.Program.Name, b.PrevMapName, value)
	return value, nil
}

// Delete the entry if its last program in the chain.
// This method is called when sequence of the program changed to last in the chain
func (b *BPF) RemoveNextProgFD() error {
	if len(b.Program.MapName) == 0 {
		// no chaining map in case of root programs
		return nil
	}
	ebpfMap, err := ebpf.LoadPinnedMap(b.Program.MapName, nil)
	if err != nil {
		return fmt.Errorf("unable to access pinned next prog map %s %v", b.Program.MapName, err)
	}
	defer ebpfMap.Close()
	key := 0

	if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
		return fmt.Errorf("failed to delete prog fd entry")
	}
	return nil
}

// Delete the entry if the last element
func (b *BPF) RemovePrevProgFD() error {

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapName, nil)
	if err != nil {
		return fmt.Errorf("unable to access pinned prev prog map %s %v", b.PrevMapName, err)
	}
	defer ebpfMap.Close()
	key := 0

	if err := ebpfMap.Delete(unsafe.Pointer(&key)); err != nil {
		// Some cases map may be empty ignore it.
		log.Debug().Err(err).Msg("RemovePrevProgFD failed")
	}
	return nil
}

// making sure program fd map's pinned file is created
func (b *BPF) VerifyPinnedMapExists(chain bool) error {

	if chain == false {
		return nil
	}

	var err error
	if len(b.Program.MapName) > 0 {
		log.Debug().Msgf("VerifyPinnedMapExists : Program %s MapName %s", b.Program.Name, b.Program.MapName)
		for i := 0; i < 10; i++ {
			if _, err = os.Stat(b.Program.MapName); err == nil {
				log.Info().Msgf("VerifyPinnedMapExists : map file created %s", b.Program.MapName)
				return nil
			}
			log.Warn().Msgf("failed to find pinned file, checking again after a second ... ")
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			err = fmt.Errorf("failed to find pinned file %s err %w", b.Program.MapName, err)
			log.Error().Err(err).Msg("")
			return err
		}
	}

	return nil
}

// making sure XDP program fd map's pinned file is removed
func (b *BPF) VerifyPinnedMapVanish(chain bool) error {

	if len(b.Program.MapName) <= 0 || b.Program.EBPFType != models.XDPType || chain == false {
		return nil
	}

	var err error
	log.Debug().Msgf("VerifyPinnedMapVanish : Program %s MapName %s", b.Program.Name, b.Program.MapName)
	for i := 0; i < 10; i++ {
		if _, err = os.Stat(b.Program.MapName); os.IsNotExist(err) {
			log.Info().Msgf("VerifyPinnedMapVanish : map file removed successfully - %s ", b.Program.MapName)
			return nil
		} else if err != nil {
			log.Warn().Err(err).Msg("VerifyPinnedMapVanish: Error checking for map file")
		} else {
			log.Warn().Msg("VerifyPinnedMapVanish: program pinned file still exists, checking again after a second")
		}
		time.Sleep(1 * time.Second)
	}

	err = fmt.Errorf("%s map file was never removed by BPF program %s err %w", b.Program.MapName, b.Program.Name, err)
	log.Error().Err(err).Msg("")
	return err
}

// This method to verify cmd and process object is populated or not
func (b *BPF) VerifyProcessObject() error {

	if b.Cmd == nil {
		err := fmt.Errorf("command object is nil - %s", b.Program.Name)
		log.Error().Err(err).Msg("")
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
			log.Error().Err(err).Msg("could not set up nsqd")
			return fmt.Errorf("could not set up nsqd: %v", err)
		}
	}

	cdbKVStore, err := VersionAnnouncerFromCDB(b.Ctx, machineHostname,
		daemonName, netNamespace, b.Program.ConfigFilePath, b.DataCenter, "", false, false, producer)
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
}
