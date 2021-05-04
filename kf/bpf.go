// Package nf provides primitives for BPF programs / Network Functions.
package kf

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"tbd/admind/models"
	"tbd/go-shared/logs"
	"tbd/sys/unix"

	"tbd/Torbit/l3afd/config"
	"tbd/Torbit/l3afd/stats"
	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"
)

var (
	execCommand           = exec.Command
	copyBufPool sync.Pool = sync.Pool{New: func() interface{} { return make([]byte, 32*1024) }}
)

const executePerm uint32 = 0111
const bpfStatus string = "RUNNING"

// BPF defines run time details for BPFProgram.
type BPF struct {
	Program      models.BPFProgram
	Cmd          *exec.Cmd
	FilePath     string // Binary file path
	RestartCount int    // To track restart count
	LogDir       string // Log dir for the BPF program
	PrevMapName  string // Map name to link
	ProgID       int    // eBPF Program ID
	// Handle race conditions in the event of restarting entire chain
	// This is to indicate processCheck monitor to avoid starting the program while this flag is set to false.
	Monitor bool
	BpfMaps map[string]BPFMap // Map name is Key
}

func NewBpfProgram(program models.BPFProgram, logDir string) *BPF {
	bpf := &BPF{
		Program:      program,
		RestartCount: 0,
		Cmd:          nil,
		FilePath:     "",
		LogDir:       logDir,
		Monitor:      false,
		BpfMaps:      make(map[string]BPFMap, 0),
	}
	return bpf
}

// Loading the Root Program for a given interface.
func LoadRootProgram(ifaceName string, direction string, eBPFType string, conf *config.Config) (*BPF, error) {

	logs.Infof("LoadRootProgram iface %s direction %s ebpfType %s", ifaceName, direction, eBPFType)
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
		logs.Errorf("failed to get root artifacts")
		return nil, err
	}

	// On l3afd crashing scenario verify root program are unloaded properly by checking existence of persisted maps
	// if map file exists then root program is still running
	if fileExists(rootProgBPF.Program.MapName) {
		logs.Warningf("previous instance of root program %s is running, stopping it ", rootProgBPF.Program.Name)
		if err := rootProgBPF.Stop(ifaceName, direction); err != nil {
			return nil, fmt.Errorf("failed to stop root program on iface %s name %s direction %s", ifaceName, rootProgBPF.Program.Name, direction)
		}
	}

	if err := rootProgBPF.Start(ifaceName, direction, true); err != nil {
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
	logs.Infof("Searching for process %s and not ppid %d", processName, myPid)
	for _, process := range processList {
		if strings.Contains(process.Executable(), psName) {
			if process.PPid() != myPid {
				logs.Warningf("found process id %d name %s ppid %d, stopping it", process.Pid(), process.Executable(), process.PPid())
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
func (b *BPF) Stop(ifaceName, direction string) error {
	if b.Program.IsUserProgram && b.Cmd == nil {
		return fmt.Errorf("BPFProgram is not running %s", b.Program.Name)
	}

	logs.Infof("Stopping BPF Program - %s", b.Program.Name)

	// Disable monitor
	b.Monitor = false

	// Removing maps
	for key, val := range b.BpfMaps {
		logs.Debugf("removing BPF maps %s value map %#v", key, val)
		delete(b.BpfMaps, key)
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
			logs.IfErrorLogf(b.Cmd.Wait(), "cmd wait at stopping bpf program %s errored", b.Program.Name)
			b.Cmd = nil
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

	logs.Infof("bpf program stop command : %s %v", cmd, args)
	prog := execCommand(cmd, args...)
	logs.IfWarningLogf(prog.Run(), "l3afd/nf : Failed to stop the program %s", b.Program.CmdStop)
	b.Cmd = nil

	return nil
}

// Start returns the last error seen, but starts bpf program.
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

	logs.Infof("BPF Program start command : %s %v", cmd, args)
	b.Cmd = execCommand(cmd, args...)
	if err := b.Cmd.Start(); err != nil {
		logs.Infof("user mode BPF program failed - %s %v", b.Program.Name, err)
		return fmt.Errorf("failed to start : %s %v", cmd, args)
	}
	if !b.Program.IsUserProgram {
		logs.Infof("no user mode BPF program - %s No Pid", b.Program.Name)
		if err := b.Cmd.Wait(); err != nil {
			return fmt.Errorf("cmd wait at starting of bpf program returned with error %w", err)
		}
		b.Cmd = nil

		// Enable monitor
		b.Monitor = true
		return nil
	}

	isRunning, err := b.isRunning()
	if isRunning == false {
		logs.Errorf("eBPF program is failed to start : %v ", err)
		return fmt.Errorf("bpf program %s failed to start %w", b.Program.Name, err)
	}

	// Fetch when prev program map is defined
	if len(b.PrevMapName) > 0 {
		// retry 10 times
		for i := 0; i < 10; i++ {
			b.ProgID, err = b.GetProgID()
			if err == nil {
				break
			}

			logs.Warningf("failed to fetch the program ID, retrying after a second ... ")
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			logs.Errorf("failed to fetch network functions program FD %w", err)
			return fmt.Errorf("failed to fetch network functions program FD %w", err)
		}
	}

	// making sure program fd map pinned file is created
	if len(b.Program.MapName) > 0 {
		for i := 0; i < 10; i++ {
			if _, err = os.Stat(b.Program.MapName); err == nil {
				break
			}
			logs.Warningf("failed to find pinned file, retrying after a second ... ")
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			logs.Errorf("failed to find pinned file %w", err)
			return fmt.Errorf("failed to find pinned file, %w", err)
		}
	}

	if len(b.Program.MapArgs) > 0 {
		if err := b.Update(direction); err != nil {
			logs.Errorf("failed to update network functions BPF maps %w", err)
			return fmt.Errorf("failed to update network functions BPF maps %w", err)
		}
	}

	logs.IfWarningLogf(b.SetPrLimits(), "failed to set resource limits")
	stats.Incr(stats.NFStartCount, b.Program.Name, direction)
	stats.Set(float64(time.Now().Unix()), stats.NFStartTime, b.Program.Name, direction)

	// Enable monitor
	b.Monitor = true

	logs.Infof("BPF program - %s started Process id %d Program ID %d", b.Program.Name, b.Cmd.Process.Pid, b.ProgID)
	return nil
}

// Updates the config map_args
func (b *BPF) Update(direction string) error {
	for _, val := range b.Program.MapArgs {
		logs.Debugf("element of map args %s", val)
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

		for _, val := range b.Program.StopArgs {
			args = append(args, "--"+val.Key)
			if len(val.Value) > 0 {
				args = append(args, "="+val.Value)
			}
		}

		prog := execCommand(cmd, args...)
		var out bytes.Buffer
		prog.Stdout = &out
		prog.Stderr = &out
		logs.IfWarningLogf(prog.Run(), "l3afd/nf : Failed to execute %s", b.Program.CmdStatus)

		outStr, errStr := string(out.Bytes()), string(out.Bytes())
		if strings.EqualFold(outStr, bpfStatus) {
			return true, nil
		}

		return false, fmt.Errorf("l3afd/nf : BPF Program not running %s", errStr)
	}

	if b.Cmd == nil {
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

		logs.IfErrorLogf(prLimit(b.Cmd.Process.Pid, unix.RLIMIT_AS, &rlimit),
			"Failed to set Memory limits - %s", b.Program.Name)
	}

	if b.Program.CPU != 0 {
		rlimit.Cur = uint64(b.Program.CPU)
		rlimit.Max = uint64(b.Program.CPU)
		logs.IfErrorLogf(prLimit(b.Cmd.Process.Pid, unix.RLIMIT_CPU, &rlimit),
			"Failed to set CPU limits - %s", b.Program.Name)
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
	logs.Infof("Downloading - %s", proximityURL.String())

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
		logs.Errorf("Failed to set prlimit for process %d and errorno %d", pid, errno)
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

	// TC maps are pinned by default
	if b.Program.EBPFType == models.TCType {
		ebpfMap, err := ebpf.LoadPinnedMap(mapName)
		if err != nil {
			return fmt.Errorf("ebpf LoadPinnedMap failed %v", err)
		}
		defer ebpfMap.Close()

		tempMapID, err := ebpfMap.ID()
		if err != nil {
			return fmt.Errorf("fetching map id failed %v", err)
		}

		ebpfInfo, err := ebpfMap.Info()
		if err != nil {
			return fmt.Errorf("fetching map info failed %v", err)
		}

		tmpBPFMap := BPFMap{
			Name:  ebpfInfo.Name,
			MapID: tempMapID,
			Type:  ebpfInfo.Type,
		}
		logs.Infof("added mapID %d Name %s Type %s", tmpBPFMap.MapID, tmpBPFMap.Name, tmpBPFMap.Type)
		b.BpfMaps[mapName] = tmpBPFMap
		return nil
	}

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
			return fmt.Errorf("failed to fetch the map object %v", err)
		}

		ebpfMap, err := ebpf.NewMapFromID(tmpMapId)
		if err != nil {
			return fmt.Errorf("failed to get NewMapFromID %v", err)
		}
		defer ebpfMap.Close()

		ebpfInfo, err := ebpfMap.Info()
		if err != nil {
			return fmt.Errorf("failed to fetch ebpfinfo %v", err)
		}

		if ebpfInfo.Name == mpName {
			tmpBPFMap := BPFMap{
				Name:  ebpfInfo.Name,
				MapID: tmpMapId,
				Type:  ebpfInfo.Type,
			}
			b.BpfMaps[mapName] = tmpBPFMap
			break
		}
		mpId = tmpMapId
	}
	return nil
}

// This method to fetch values from bpf maps and publish to metrics
func (b *BPF) MonitorMaps() error {
	for _, element := range b.Program.MonitorMaps {
		logs.Debugf("monitor maps element %s ", element)
		bpfMap, ok := b.BpfMaps[element]
		if !ok {
			if err := b.AddBPFMap(element); err != nil {
				return fmt.Errorf("not able to fetch map %s", element)
			}
		}
		bpfMap, _ = b.BpfMaps[element]
		stats.SetValue(float64(bpfMap.GetValue()), stats.NFMointorMap, b.Program.Name, element)
	}
	return nil
}

func (b *BPF) GetNextProgID() (int, error) {
	if len(b.Program.MapName) == 0 {
		// no chaining map
		return 0, nil
	}
	ebpfMap, err := ebpf.LoadPinnedMap(b.Program.MapName)
	if err != nil {
		return 0, fmt.Errorf("unable to access pinned next prog map %s %v", b.Program.MapName, err)
	}
	defer ebpfMap.Close()

	var value int
	key := 0
	if err := ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		if strings.Contains(fmt.Sprint(err), "key does not exist") {
			return 0, nil
		}
		return 0, fmt.Errorf("unable to lookup next prog map %s %v", b.Program.MapName, err)
	}

	return value, nil
}

// Updating next program FD from program ID
func (b *BPF) PutNextProgFDFromID(progID int) error {

	if len(b.Program.MapName) == 0 {
		// no chaining map
		return nil
	}

	ebpfMap, err := ebpf.LoadPinnedMap(b.Program.MapName)
	if err != nil {
		return fmt.Errorf("unable to access pinned next prog map %s %v", b.Program.MapName, err)
	}
	defer ebpfMap.Close()

	bpfProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return fmt.Errorf("failed to get next prog FD from ID for program %s %v", b.Program.Name, err)
	}
	key := 0
	if err = ebpfMap.Put(unsafe.Pointer(&key), uint32(bpfProg.FD())); err != nil {
		return fmt.Errorf("unable to update prog next map %s %v", b.Program.MapName, err)
	}
	return nil
}

// This returns ID of the bpf program
func (b *BPF) GetProgID() (int, error) {

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapName)
	if err != nil {
		logs.Errorf("unable to access pinned prog map %s %w", b.PrevMapName, err)
		return 0, fmt.Errorf("unable to access pinned prog map %s %v", b.PrevMapName, err)
	}
	defer ebpfMap.Close()
	var value int
	key := 0

	if err = ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		if err != nil {
			logs.Warningf("unable to lookup prog map %s", b.PrevMapName)
			return 0, fmt.Errorf("unable to lookup prog map %w", err)
		}
	}

	logs.Infof("GetProgID - Name %s PrevMapName %s ID %d", b.Program.Name, b.PrevMapName, value)
	return value, nil
}

// Delete the entry if the last element
func (b *BPF) RemoveNextProgFD() error {
	if len(b.Program.MapName) == 0 {
		// no chaining map in case of root programs
		return nil
	}
	ebpfMap, err := ebpf.LoadPinnedMap(b.Program.MapName)
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
