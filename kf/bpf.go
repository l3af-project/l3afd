// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

// Package kf provides primitives for BPF programs / Network Functions.
package kf

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"container/ring"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
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

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/models"
	"github.com/l3af-project/l3afd/stats"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
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
	Program         models.BPFProgram
	Cmd             *exec.Cmd
	FilePath        string                    // Binary file path
	RestartCount    int                       // To track restart count
	PrevMapNamePath string                    // Previous Map name with path to link
	MapNamePath     string                    // Map name with path
	ProgID          int                       // eBPF Program ID
	BpfMaps         map[string]BPFMap         // Config maps passed as map-args, Map name is Key
	MetricsBpfMaps  map[string]*MetricsBPFMap // Metrics map name+key+aggregator is key
	Ctx             context.Context
	Done            chan bool `json:"-"`
	hostConfig      *config.Config
}

func NewBpfProgram(ctx context.Context, program models.BPFProgram, conf *config.Config) *BPF {
	bpf := &BPF{
		Program:        program,
		RestartCount:   0,
		Cmd:            nil,
		FilePath:       "",
		BpfMaps:        make(map[string]BPFMap, 0),
		MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
		Ctx:            ctx,
		Done:           nil,
		hostConfig:     conf,
		MapNamePath:    filepath.Join(conf.BpfMapDefaultPath, program.MapName),
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
				Name:              conf.XDPRootProgramName,
				Artifact:          conf.XDPRootProgramArtifact,
				MapName:           conf.XDPRootProgramMapName,
				Version:           conf.XDPRootProgramVersion,
				UserProgramDaemon: false,
				CmdStart:          conf.XDPRootProgramCommand,
				CmdStop:           conf.XDPRootProgramCommand,
				CmdStatus:         "",
				AdminStatus:       models.Enabled,
				ProgType:          models.XDPType,
				SeqID:             0,
				StartArgs:         map[string]interface{}{},
				StopArgs:          map[string]interface{}{},
				StatusArgs:        map[string]interface{}{},
				ObjectFile:        filepath.Join(conf.BPFDir, conf.XDPRootProgramName, conf.XDPRootProgramVersion, strings.Split(conf.XDPRootProgramArtifact, ".")[0], conf.XDPRootProgramObjectFile),
			},
			RestartCount:    0,
			Cmd:             nil,
			FilePath:        "",
			PrevMapNamePath: "",
			hostConfig:      conf,
			MapNamePath:     filepath.Join(conf.BpfMapDefaultPath, conf.XDPRootProgramMapName),
		}
	case models.TCType:
		rootProgBPF = &BPF{
			Program: models.BPFProgram{
				Name:              conf.TCRootProgramName,
				Artifact:          conf.TCRootProgramArtifact,
				Version:           conf.TCRootProgramVersion,
				UserProgramDaemon: false,
				CmdStart:          conf.TCRootProgramCommand,
				CmdStop:           conf.TCRootProgramCommand,
				CmdStatus:         "",
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
			hostConfig:      conf,
		}
		if direction == models.IngressType {
			rootProgBPF.Program.MapName = conf.TCRootProgramIngressMapName
			rootProgBPF.MapNamePath = filepath.Join(conf.BpfMapDefaultPath, conf.TCRootProgramIngressMapName)
			rootProgBPF.Program.ObjectFile = filepath.Join(conf.BPFDir, conf.TCRootProgramName, conf.TCRootProgramVersion, strings.Split(conf.TCRootProgramArtifact, ".")[0], conf.TCRootProgramIngressObjectFile)
		} else if direction == models.EgressType {
			rootProgBPF.Program.MapName = conf.TCRootProgramEgressMapName
			rootProgBPF.MapNamePath = filepath.Join(conf.BpfMapDefaultPath, conf.TCRootProgramEgressMapName)
			rootProgBPF.Program.ObjectFile = filepath.Join(conf.BPFDir, conf.TCRootProgramName, conf.TCRootProgramVersion, strings.Split(conf.TCRootProgramArtifact, ".")[0], conf.TCRootProgramEgressObjectFile)
		}
	default:
		return nil, fmt.Errorf("unknown direction %s for root program in iface %s", direction, ifaceName)
	}

	// Loading default arguments
	//rootProgBPF.Program.StartArgs["cmd"] = models.StartType
	//rootProgBPF.Program.StopArgs["cmd"] = models.StopType

	if err := rootProgBPF.VerifyAndGetArtifacts(conf); err != nil {
		log.Error().Err(err).Msg("failed to get root artifacts")
		return nil, err
	}

	// On l3afd crashing scenario verify root program are unloaded properly by checking existence of persisted maps
	// if map file exists then root program is still running
	if fileExists(rootProgBPF.MapNamePath) {
		log.Warn().Msgf("previous instance of root program %s is running, stopping it ", rootProgBPF.Program.Name)
		if err := rootProgBPF.Stop(ifaceName, direction, conf.BpfChainingEnabled); err != nil {
			return nil, fmt.Errorf("failed to stop root program on iface %s name %s direction %s", ifaceName, rootProgBPF.Program.Name, direction)
		}
	}

	//if err := rootProgBPF.Start(ifaceName, direction, conf.BpfChainingEnabled); err != nil {
	//	return nil, fmt.Errorf("failed to start root program on interface %s, err: %v", ifaceName, err)
	//}
	// objectFile := filepath.Join(conf.BPFDir, rootProgBPF.Program.Name, rootProgBPF.Program.Version, strings.Split(rootProgBPF.Program.Artifact, ".")[0], rootProgBPF.Program.ObjectFile)
	fmt.Println("object file - ", rootProgBPF.Program.ObjectFile)
	if progType == models.XDPType {
		rlimit.RemoveMemlock()
		if err := LoadXDPRootProgram(ifaceName, rootProgBPF); err != nil {
			return nil, fmt.Errorf("failed to load root program on iface %s name %s direction %s", ifaceName, rootProgBPF.Program.Name, direction)
		}
	} else if progType == models.TCType {
		if err := LoadTCRootProgram(ifaceName, direction, rootProgBPF); err != nil {
			return nil, fmt.Errorf("failed to load root program on iface %s name %s direction %s", ifaceName, rootProgBPF.Program.Name, direction)
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
		return fmt.Errorf("failed to fetch processes list")
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
					return fmt.Errorf("external BPFProgram stop failed with error: %v", err)
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
		if err := b.ProcessTerminate(); err != nil {
			return fmt.Errorf("BPFProgram %s process terminate failed with error: %v", b.Program.Name, err)
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

		// Verify all metrics map references are removed from kernel
		if err := b.VerifyMetricsMapsVanish(); err != nil {
			log.Error().Err(err).Msgf("stop user program - failed to remove metric map references %s", b.Program.Name)
			return fmt.Errorf("stop user program - failed to remove metric map references %s", b.Program.Name)
		}

		return nil
	}

	cmd := filepath.Join(b.FilePath, b.Program.CmdStop)

	if err := assertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %v", b.Program.CmdStop, err)
	}

	args := make([]string, 0, len(b.Program.StopArgs)<<1)
	args = append(args, "--iface="+ifaceName)     // detaching from iface
	args = append(args, "--direction="+direction) // xdpingress or ingress or egress

	for k, val := range b.Program.StopArgs {
		if v, ok := val.(string); !ok {
			err := fmt.Errorf("stop args is not a string for the ebpf program %s", b.Program.Name)
			log.Error().Err(err).Msgf("failed to convert stop args value into string for program %s", b.Program.Name)
			return err
		} else {
			args = append(args, "--"+k+"="+v)
		}
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

	// Verify all metrics map references are removed from kernel
	if err := b.VerifyMetricsMapsVanish(); err != nil {
		log.Error().Err(err).Msgf("failed to remove metric map references %s", b.Program.Name)
		return fmt.Errorf("failed to remove metric map references %s", b.Program.Name)
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
		return fmt.Errorf("failed to stop external instance of the program %s with error : %v", b.Program.CmdStart, err)
	}

	cmd := filepath.Join(b.FilePath, b.Program.CmdStart)
	// Validate
	if err := assertExecutable(cmd); err != nil {
		return fmt.Errorf("no executable permissions on %s - error %v", b.Program.CmdStart, err)
	}

	// Making sure old map entry is removed before passing the prog fd map to the program.
	if len(b.PrevMapNamePath) > 0 {
		if err := b.RemovePrevProgFD(); err != nil {
			log.Error().Err(err).Msgf("ProgramMap %s entry removal failed", b.PrevMapNamePath)
		}
	}

	args := make([]string, 0, len(b.Program.StartArgs)<<1)
	args = append(args, "--iface="+ifaceName)     // attaching to interface
	args = append(args, "--direction="+direction) // direction xdpingress or ingress or egress

	if chain {
		if len(b.PrevMapNamePath) > 1 {
			args = append(args, "--map-name="+b.PrevMapNamePath)
		}
	}

	if len(b.hostConfig.BPFLogDir) > 1 {
		args = append(args, "--log-dir="+b.hostConfig.BPFLogDir)
	}

	if len(b.Program.RulesFile) > 1 && len(b.Program.Rules) > 1 {
		fileName, err := b.createUpdateRulesFile(direction)
		if err == nil {
			args = append(args, "--rules-file="+fileName)
		}
	}

	for k, val := range b.Program.StartArgs {
		if v, ok := val.(string); !ok {
			err := fmt.Errorf("start args is not a string for the ebpf program %s", b.Program.Name)
			log.Error().Err(err).Msgf("failed to convert start args value into string for program %s", b.Program.Name)
			return err
		} else {
			args = append(args, "--"+k+"="+v)
		}
	}

	log.Info().Msgf("BPF Program start command : %s %v", cmd, args)
	b.Cmd = execCommand(cmd, args...)
	if err := b.Cmd.Start(); err != nil {
		log.Info().Err(err).Msgf("user mode BPF program failed - %s", b.Program.Name)
		return fmt.Errorf("failed to start : %s %v", cmd, args)
	}
	if !b.Program.UserProgramDaemon {
		log.Info().Msgf("no user mode BPF program - %s No Pid", b.Program.Name)
		if err := b.Cmd.Wait(); err != nil {
			return fmt.Errorf("cmd wait at starting of bpf program returned with error %v", err)
		}
		b.Cmd = nil

		if err := b.VerifyPinnedMapExists(chain); err != nil {
			return fmt.Errorf("no userprogram and failed to find pinned file %s, %v", b.MapNamePath, err)
		}
		return nil
	}

	isRunning, err := b.isRunning()
	if !isRunning {
		log.Error().Err(err).Msg("eBPF program failed to start")
		return fmt.Errorf("bpf program %s failed to start %v", b.Program.Name, err)
	}

	// making sure program fd map pinned file is created
	if err := b.VerifyPinnedMapExists(chain); err != nil {
		return fmt.Errorf("failed to find pinned file %s  %v", b.MapNamePath, err)
	}

	if len(b.Program.MapArgs) > 0 {
		if err := b.Update(ifaceName, direction); err != nil {
			log.Error().Err(err).Msg("failed to update network functions BPF maps")
			return fmt.Errorf("failed to update network functions BPF maps %v", err)
		}
	}

	// Fetch when prev program map is updated
	if len(b.PrevMapNamePath) > 0 {
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
			return fmt.Errorf("failed to fetch network functions program FD %v", err)
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
	for k, val := range b.Program.MapArgs {

		if v, ok := val.(string); !ok {
			err := fmt.Errorf("update map args is not a string for the ebpf program %s", b.Program.Name)
			log.Error().Err(err).Msgf("failed to convert map args value into string for program %s", b.Program.Name)
			return err
		} else {
			log.Info().Msgf("Update map args key %s val %s", k, v)

			bpfMap, ok := b.BpfMaps[k]
			if !ok {
				if err := b.AddBPFMap(k); err != nil {
					return err
				}
				bpfMap = b.BpfMaps[k]
			}
			bpfMap.Update(v)
		}
	}
	stats.Incr(stats.NFUpdateCount, b.Program.Name, direction)
	return nil
}

// Status of user program is running
func (b *BPF) isRunning() (bool, error) {
	// No user program or may be disabled
	if len(b.Program.CmdStatus) > 1 {
		cmd := filepath.Join(b.FilePath, b.Program.CmdStatus)

		if err := assertExecutable(cmd); err != nil {
			return false, fmt.Errorf("failed to execute %s with error: %v", b.Program.CmdStatus, err)
		}

		args := make([]string, 0, len(b.Program.StatusArgs)<<1)

		for k, val := range b.Program.StatusArgs {
			if v, ok := val.(string); !ok {
				err := fmt.Errorf("status args is not a string for the ebpf program %s", b.Program.Name)
				log.Error().Err(err).Msgf("failed to convert status args value into string for program %s", b.Program.Name)
				return false, err
			} else {
				args = append(args, "--"+k+"="+v)
			}
		}

		prog := execCommand(cmd, args...)
		var out bytes.Buffer
		prog.Stdout = &out
		prog.Stderr = &out
		if err := prog.Run(); err != nil {
			log.Warn().Err(err).Msgf("l3afd/nf : Failed to execute %s", b.Program.CmdStatus)
		}

		outStr, errStr := out.String(), out.String()
		if strings.EqualFold(outStr, bpfStatus) {
			return true, nil
		}

		return false, fmt.Errorf("l3afd/nf : BPF Program not running %s", errStr)
	}

	// No running user program and command status is not provided then return true
	if !b.Program.UserProgramDaemon {
		return true, nil
	}

	if err := b.VerifyProcessObject(); err != nil {
		return false, errors.New("no process id found")
	}

	return IsProcessRunning(b.Cmd.Process.Pid, b.Program.Name)
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

// GetArtifacts downloads artifacts from the specified eBPF repo
func (b *BPF) GetArtifacts(conf *config.Config) error {

	buf := &bytes.Buffer{}
	isDefaultURLUsed := false
	platform, err := GetPlatform()
	if err != nil {
		return fmt.Errorf("failed to identify platform type: %v", err)
	}

	RepoURL := b.Program.EPRURL
	if len(b.Program.EPRURL) == 0 {
		RepoURL = conf.EBPFRepoURL
		isDefaultURLUsed = true
	}

	URL, err := url.Parse(RepoURL)
	if err != nil {
		if isDefaultURLUsed {
			return fmt.Errorf("unknown ebpf-repo format : %v", err)
		} else {
			return fmt.Errorf("unknown ebpf_package_repo_url format : %v", err)
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
				return fmt.Errorf("download failed: %v", err)
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
					return fmt.Errorf("opening err : %v", err)
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
				return fmt.Errorf("failed to create zip reader: %v", err)
			}
			tempDir := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version)

			for _, file := range zipReader.File {

				zippedFile, err := file.Open()
				if err != nil {
					return fmt.Errorf("unzip failed: %v", err)
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
						return fmt.Errorf("unzip failed to create file: %v", err)
					}
					defer outputFile.Close()

					buf := copyBufPool.Get().(*bytes.Buffer)
					_, err = io.CopyBuffer(outputFile, zippedFile, buf.Bytes())
					if err != nil {
						return fmt.Errorf("GetArtifacts failed to copy files: %v", err)
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
				return fmt.Errorf("failed to create Gzip reader: %v", err)
			}
			defer archive.Close()
			tarReader := tar.NewReader(archive)
			tempDir := filepath.Join(conf.BPFDir, b.Program.Name, b.Program.Version)

			for {
				header, err := tarReader.Next()

				if err == io.EOF {
					break
				} else if err != nil {
					return fmt.Errorf("untar failed: %v", err)
				}

				fPath, err := ValidatePath(header.Name, tempDir)
				if err != nil {
					return err
				}

				info := header.FileInfo()
				if info.IsDir() {
					if err = os.MkdirAll(fPath, info.Mode()); err != nil {
						return fmt.Errorf("untar failed to create directories: %v", err)
					}
					continue
				}

				file, err := os.OpenFile(fPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
				if err != nil {
					return fmt.Errorf("untar failed to create file: %v", err)
				}
				defer file.Close()

				buf := copyBufPool.Get().(*bytes.Buffer)
				_, err = io.CopyBuffer(file, tarReader, buf.Bytes())
				if err != nil {
					return fmt.Errorf("GetArtifacts failed to copy files: %v", err)
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
		return "", fmt.Errorf("create or Update Rules File failed with error %v", err)
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
	if b.Program.ProgType == models.TCType {
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
			Name:    mapName,
			MapID:   tempMapID,
			Type:    ebpfInfo.Type,
			BPFProg: b,
		}

	} else if b.Program.ProgType == models.XDPType {

		// XDP maps
		// map names are truncated to 15 chars
		mpName := mapName
		if len(mapName) > 15 {
			mpName = mapName[:15]
			log.Warn().Msgf("searching map name of first 15 chars %s", mpName)
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
					Name:    mapName,
					MapID:   tmpMapId,
					Type:    ebpfInfo.Type,
					BPFProg: b,
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
		log.Debug().Msgf("monitor maps element %s key %d aggregator %s", element.Name, element.Key, element.Aggregator)
		mapKey := element.Name + strconv.Itoa(element.Key) + element.Aggregator
		_, ok := b.MetricsBpfMaps[mapKey]
		if !ok {
			if err := b.AddMetricsBPFMap(element.Name, element.Aggregator, element.Key, intervals); err != nil {
				return fmt.Errorf("not able to fetch map %s key %d aggregator %s", element.Name, element.Key, element.Aggregator)
			}
		}
		bpfMap := b.MetricsBpfMaps[mapKey]
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
	ebpfMap, err := ebpf.LoadPinnedMap(b.MapNamePath, nil)
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

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapNamePath, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		log.Error().Err(err).Msgf("unable to access pinned prog map %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("unable to access pinned prog map %s %v", b.PrevMapNamePath, err)
	}
	defer ebpfMap.Close()
	var value int
	key := 0

	if err = ebpfMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		log.Warn().Err(err).Msgf("unable to lookup prog map %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("unable to lookup prog map %v", err)
	}

	// verify progID before storing in locally.
	_, err = ebpf.NewProgramFromID(ebpf.ProgramID(value))
	if err != nil {
		log.Warn().Err(err).Msgf("failed to verify program ID %s", b.PrevMapNamePath)
		return 0, fmt.Errorf("failed to verify program ID %s %v", b.Program.Name, err)
	}

	log.Info().Msgf("GetProgID - Name %s PrevMapName %s ID %d", b.Program.Name, b.PrevMapNamePath, value)
	return value, nil
}

// Delete the entry if its last program in the chain.
// This method is called when sequence of the program changed to last in the chain
func (b *BPF) RemoveNextProgFD() error {
	if len(b.Program.MapName) == 0 {
		// no chaining map in case of root programs
		return nil
	}
	ebpfMap, err := ebpf.LoadPinnedMap(b.MapNamePath, nil)
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

	ebpfMap, err := ebpf.LoadPinnedMap(b.PrevMapNamePath, nil)
	if err != nil {
		return fmt.Errorf("unable to access pinned prev prog map %s %v", b.PrevMapNamePath, err)
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

	if !chain {
		return nil
	}

	var err error
	if len(b.Program.MapName) > 0 {
		log.Debug().Msgf("VerifyPinnedMapExists : Program %s MapName %s", b.Program.Name, b.Program.MapName)

		for i := 0; i < 10; i++ {
			if _, err = os.Stat(b.MapNamePath); err == nil {
				log.Info().Msgf("VerifyPinnedMapExists : map file created %s", b.MapNamePath)
				return nil
			}
			log.Warn().Msgf("failed to find pinned file, checking again after a second ... ")
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			err = fmt.Errorf("failed to find pinned file %s err %v", b.MapNamePath, err)
			log.Error().Err(err).Msg("")
			return err
		}
	}

	return nil
}

// VerifyPinnedMapVanish - making sure XDP program fd map's pinned file is removed
func (b *BPF) VerifyPinnedMapVanish(chain bool) error {

	if len(b.Program.MapName) <= 0 || b.Program.ProgType != models.XDPType || !chain {
		return nil
	}

	var err error
	log.Debug().Msgf("VerifyPinnedMapVanish : Program %s MapName %s", b.Program.Name, b.Program.MapName)

	for i := 0; i < 10; i++ {
		if _, err = os.Stat(b.MapNamePath); os.IsNotExist(err) {
			log.Info().Msgf("VerifyPinnedMapVanish : map file removed successfully - %s ", b.MapNamePath)
			return nil
		} else if err != nil {
			log.Warn().Err(err).Msg("VerifyPinnedMapVanish: Error checking for map file")
		} else {
			log.Warn().Msg("VerifyPinnedMapVanish: program pinned file still exists, checking again after a second")
		}
		time.Sleep(1 * time.Second)
	}

	err = fmt.Errorf("%s map file was never removed by BPF program %s err %v", b.MapNamePath, b.Program.Name, err)
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

func LoadXDPRootProgram(ifaceName string, eBPFProgram *BPF) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal().Msgf("lookup network iface %q: %s", ifaceName, err)
	}

	prg, err := ebpf.LoadCollection(eBPFProgram.Program.ObjectFile)
	if err != nil {
		fmt.Println("LoadCollection xdp root error : ", err)
		return fmt.Errorf("%s: loading of xdp root filed", eBPFProgram.Program.ObjectFile)
	}
	defer prg.Close()

	var bpfRootProg, bpfPassProg ebpf.Program
	for key, value := range prg.Programs {
		fmt.Println("Key : ", key, "Value : ", *value, "Program Type : ", (*value).Type())
		if key == eBPFProgram.hostConfig.XDPRootProgramName {
			bpfRootProg = *value
			fmt.Println("bpfRootProg assigned ", bpfRootProg)
			fmt.Println("bpfRootProg assigned value ", *value)
		} else if key == eBPFProgram.hostConfig.XDPRootProgramPassProgName {
			bpfPassProg = *value
		}
	}
	fmt.Println("bpfRootProg assigned after ", bpfRootProg)
	var bpfRootMap, bpfPassMap ebpf.Map
	for key, value := range prg.Maps {
		fmt.Println("Key : ", key, "Value : ", *value, "Program Type : ", (*value).Type())
		if key == eBPFProgram.hostConfig.XDPRootProgramMapName {
			bpfRootMap = *value
		} else if key == eBPFProgram.hostConfig.XDPRootProgramPassMapName {
			bpfPassMap = *value
		}
	}

	rootArrayMapFileName := filepath.Join("/sys/fs/bpf/", eBPFProgram.Program.MapName)
	if err := bpfRootMap.Pin(rootArrayMapFileName); err != nil {
		fmt.Println("map pinning failed", err)
		return fmt.Errorf("%s:failed to pin the map", rootArrayMapFileName)
	}

	//root_prog_map_file := "/sys/fs/bpf/xdp_root_array"
	passProgMapFileName := filepath.Join("/sys/fs/bpf/", eBPFProgram.hostConfig.XDPRootProgramPassMapName)
	if err := bpfPassMap.Pin(passProgMapFileName); err != nil {
		fmt.Println("map pinning failed", err)
		return fmt.Errorf("%s:failed to pin the map", passProgMapFileName)
	}

	fmt.Println("iface ", iface)
	fmt.Println("bpfRootProg ", bpfRootProg)
	// fmt.Println("program Type : ", bpfRootProg.Type())
	// Attach the program.
	_, err = link.AttachXDP(link.XDPOptions{
		Program:   &bpfRootProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Error().Msgf("could not attach XDP program: %s", err)
		return fmt.Errorf("could not attach XDP program: %s", err)
	}

	var passProgMap ebpf.Map
	for key, value := range prg.Maps {
		if key == eBPFProgram.hostConfig.XDPRootProgramPassMapName {
			passProgMap = *value
			break
		}
	}

	key := 0
	if err := passProgMap.Update(unsafe.Pointer(&key), uint32(bpfPassProg.FD()), 0); err != nil {
		fmt.Println("ebpfMap.Update error ", err)
		return fmt.Errorf("%s:failed to update the pass program id in the map", eBPFProgram.hostConfig.XDPRootProgramPassMapName)
	}

	return nil
}

func LoadTCRootProgram(ifaceName string, direction string, eBPFProgram *BPF) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal().Msgf("lookup network iface %q: %s", ifaceName, err)
	}

	// verify and add attribute clsact
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return fmt.Errorf("could not open rtnetlink socket: %v\n", err)
	}

	clsactFound := false
	// get all the qdiscs from all interfaces
	qdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return fmt.Errorf("could not get qdiscs: %v\n", err)
	}
	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		if err != nil {
			return fmt.Errorf("could not get interface from id %d: %v", qdisc.Ifindex, err)
		}
		if iface.Name == ifaceName && qdisc.Kind == "clsact" {
			clsactFound = true
		}
		fmt.Printf("%20s\t%s\n", iface.Name, qdisc.Kind)
	}

	if clsactFound == false {
		qdisc := tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
				Parent:  tc.HandleIngress,
				Info:    0,
			},
			Attribute: tc.Attribute{
				Kind: "clsact",
			},
		}

		if err := tcnl.Qdisc().Add(&qdisc); err != nil {
			log.Info().Msgf("could not assign clsact to %s: %v\n its already exists", ifaceName, err)
		}
	}

	prg, err := ebpf.LoadCollection(eBPFProgram.Program.ObjectFile)
	if err != nil {
		fmt.Println("LoadCollection tc root error : ", err)
		return fmt.Errorf("%s: loading of tc root filed", eBPFProgram.Program.ObjectFile)
	}
	//defer prg.Close()

	var bpfRootProg, bpfPassProg ebpf.Program
	var rootArrayMapFileName, passProgMapFileName string
	if direction == models.IngressType {
		for key, value := range prg.Programs {
			fmt.Println("Key : ", key, "Value : ", value)
			fmt.Println("eBPFProgram.hostConfig.TCRootProgramIngressProgName: ", eBPFProgram.hostConfig.TCRootProgramIngressProgName)
			fmt.Println("eBPFProgram.hostConfig.TCRootProgramIngressPassProgName: ", eBPFProgram.hostConfig.TCRootProgramIngressPassProgName)
			if key == eBPFProgram.hostConfig.TCRootProgramIngressProgName {
				fmt.Println("Key : ", key, "tc_ingress_root found")
				bpfRootProg = *value
			} else if key == eBPFProgram.hostConfig.TCRootProgramIngressPassProgName {
				fmt.Println("Key : ", key, "tc_ingress_pass_through found")
				bpfPassProg = *value
			}
		}
		rootArrayMapFileName = filepath.Join("/sys/fs/bpf/", eBPFProgram.Program.MapName)
		passProgMapFileName = filepath.Join("/sys/fs/bpf/", eBPFProgram.hostConfig.TCRootProgramIngressPassMapName)
	} else if direction == models.EgressType {
		for key, value := range prg.Programs {
			fmt.Println("Key : ", key, "Value : ", value)
			if key == eBPFProgram.hostConfig.TCRootProgramEgressProgName {
				fmt.Println("Key : ", key, "tc_ingress_root found")
				bpfRootProg = *value
			} else if key == eBPFProgram.hostConfig.TCRootProgramEgressPassProgName {
				fmt.Println("Key : ", key, "tc_ingress_pass_through found")
				bpfPassProg = *value
			}
		}
		rootArrayMapFileName = filepath.Join("/sys/fs/bpf/", eBPFProgram.Program.MapName)
		passProgMapFileName = filepath.Join("/sys/fs/bpf/", eBPFProgram.hostConfig.TCRootProgramEgressPassMapName)
	}

	fmt.Println("passProgMapFileName - ", passProgMapFileName)
	fmt.Println("rootArrayMapFileName - ", rootArrayMapFileName)
	if err := bpfRootProg.Pin(passProgMapFileName); err != nil {
		fmt.Println("map pinning failed - tc_root_pass_array", err)
		return fmt.Errorf("%s:failed to pin the map", passProgMapFileName)
	}

	if err := bpfPassProg.Pin(rootArrayMapFileName); err != nil {
		fmt.Println("map pinning failed - tc_root_array name ", rootArrayMapFileName, "error ", err)
		return fmt.Errorf("%s:failed to pin the map", rootArrayMapFileName)
	}

	var parent uint32
	var passProgMapName string
	if direction == models.IngressType {
		parent = tc.HandleMinIngress
		passProgMapName = strings.Split(eBPFProgram.hostConfig.TCRootProgramIngressPassMapName, "/")[2]
	} else if direction == models.IngressType {
		parent = tc.HandleMinEgress
		passProgMapName = strings.Split(eBPFProgram.hostConfig.TCRootProgramEgressPassMapName, "/")[2]
	}

	progFD := uint32(bpfRootProg.FD())
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, parent),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD: &progFD,
			},
		},
	}
	
	fmt.Println("before TC filter Add - ")
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Println("could not attach filter for eBPF program:", err)
		return fmt.Errorf("could not attach filter for eBPF program: %v\n", err)
	}
	fmt.Println("After  TC filter Add - ")
	fmt.Println("passProgMapName - ", passProgMapName)
	var passProgMap ebpf.Map
	for key, value := range prg.Maps {
		fmt.Println("Map Key - ", key, " value - ", value)
		if key == passProgMapName {
			fmt.Println("Map Found - ", key)
			passProgMap = *value
			break
		}
	}

	key := 0
	if err := passProgMap.Update(unsafe.Pointer(&key), uint32(bpfPassProg.FD()), 0); err != nil {
		fmt.Println("ebpfMap.Update error ", err)
		return fmt.Errorf("%s:failed to update the map", passProgMapName)
	}

	return nil
}
