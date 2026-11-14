// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/mocks"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/stats"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"go.uber.org/mock/gomock"
)

var mockedExitStatus = 1
var mockPid = 77

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	cmd.Process = &os.Process{Pid: mockPid}
	return cmd
}

// fakeExecCommandDaemon is like fakeExecCommand but keeps the spawned helper
// process alive for a bit instead of exiting immediately. It's used for
// daemon-mode (UserProgramDaemon=true) scenarios where the code under test
// checks isRunning() right after Start(): a real short-lived binary (e.g.
// /bin/date) or an instantly-exiting helper process can already be a zombie
// by the time that check runs, making the test racy/flaky.
func fakeExecCommandDaemon(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "GO_HELPER_SLEEP=1"}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("GO_HELPER_SLEEP") == "1" {
		time.Sleep(2 * time.Second)
	}
	os.Exit(mockedExitStatus)
}

func TestNewBpfProgram(t *testing.T) {
	type args struct {
		program    models.BPFProgram
		logDir     string
		chain      bool
		direction  string
		ctx        context.Context
		datacenter string
		hostConfig *config.Config
	}
	execCommand = fakeExecCommand
	defer func() { execCommand = exec.Command }()
	tests := []struct {
		name string
		args args
		want *BPF
	}{
		{name: "GoodInput",
			args: args{
				program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "foo.tar.gz",
					CmdStart:          "foo",
					CmdStop:           "",
					CmdConfig:         "",
					Version:           "1.0",
					UserProgramDaemon: true,
					IsPlugin:          false,
					AdminStatus:       "enabled",
					ProgType:          "tc",
				},
				logDir:     "",
				chain:      false,
				direction:  "ingress",
				datacenter: "localdc",
				hostConfig: &config.Config{
					BPFLogDir:  "",
					DataCenter: "localdc",
				},
			},
			want: &BPF{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "foo.tar.gz",
					CmdStart:          "foo",
					CmdStop:           "",
					CmdConfig:         "",
					CmdUpdate:         "",
					Version:           "1.0",
					UserProgramDaemon: true,
					IsPlugin:          false,
					AdminStatus:       "enabled",
					ProgType:          "tc",
				},
				Cmd:            nil,
				FilePath:       "",
				BpfMaps:        make(map[string]BPFMap, 0),
				MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
				Ctx:            nil,
				Done:           nil,
				HostConfig: &config.Config{
					BPFLogDir:  "",
					DataCenter: "localdc",
				},
				IfaceName: ifaceName,
			},
		},
		{name: "EmptyBPFProgram",
			args: args{
				program:    models.BPFProgram{},
				hostConfig: &config.Config{},
			},
			want: &BPF{
				Program:        models.BPFProgram{},
				Cmd:            nil,
				FilePath:       "",
				BpfMaps:        make(map[string]BPFMap, 0),
				MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
				HostConfig:     &config.Config{},
				IfaceName:      ifaceName,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewBpfProgram(tt.args.ctx, tt.args.program, tt.args.hostConfig, ifaceName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewBpfProgram() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestBPF_Stop(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		Direction    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{name: "NilCmd",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "foo.tar.gz",
					CmdStart:          "foo",
					CmdStop:           "",
					Version:           "1.0",
					UserProgramDaemon: true,
					AdminStatus:       "enabled",
				},
				Cmd:          nil,
				FilePath:     "/tmp/dummy/dummy",
				RestartCount: 3,
			},
			wantErr: true,
		},
		{name: "WithStopCmd",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "foo.tar.gz",
					CmdStart:          "foo",
					CmdStop:           "foo",
					Version:           "1.0",
					UserProgramDaemon: true,
					AdminStatus:       "enabled",
				},
				Cmd:          fakeExecCommand("/tmp/dummy/foo"),
				FilePath:     "/tmp/dummy/dummy",
				RestartCount: 3,
			},
			wantErr: true,
		},
		{name: "AnyBinaryFile",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "data.tar.gz",
					CmdStart:          GetTestExecutableName(),
					CmdStop:           GetTestExecutableName(),
					UserProgramDaemon: false,
					AdminStatus:       "enabled",
				},
				Cmd:          fakeExecCommand(GetTestExecutablePathName()),
				FilePath:     GetTestExecutablePath(),
				RestartCount: 3,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}

			// Create the metric with expected labels
			stats.BPFRunning = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: "l3afd_BPFRunning",
					Help: "Indicates whether eBPF program is running",
				},
				[]string{"program", "version", "direction", "iface"},
			)

			if err := prometheus.Register(stats.BPFRunning); err != nil {
				log.Warn().Err(err).Msg("Failed to register BPFRunning metrics")
			}

			// Simulate program load
			stats.BPFRunning.With(prometheus.Labels{
				"program":   b.Program.Name,
				"version":   b.Program.Version,
				"direction": "ingress",
				"iface":     "eth0",
			}).Set(1)

			stats.BPFStartTime = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "l3afd",
					Name:      "BPFStartTime",
					Help:      "This value indicates start time of the BPF program since unix epoch in seconds",
				},
				[]string{"host", "ebpf_program", "direction", "interface_name"},
			)

			if err := prometheus.Register(stats.BPFStartTime); err != nil {
				log.Warn().Err(err).Msg("Failed to register BPFStartTime metrics")
			}

			if err := b.Stop(ifaceName, "", models.IngressType, false); (err != nil) != tt.wantErr {
				t.Errorf("BPF.Stop() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBPF_Start(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		ifaceName    string
		hostConfig   *config.Config
	}
	tests := []struct {
		name string
		// mockDaemon makes Start() use a fake, deliberately long-lived
		// execCommand instead of really running fields.Program.CmdStart.
		// Needed for UserProgramDaemon=true cases: Start() checks
		// isRunning() immediately after launch, and a real short-lived
		// binary (e.g. /bin/date) can already be a zombie by then,
		// making the test racy/flaky.
		mockDaemon bool
		fields     fields
		wantErr    bool
	}{
		{name: "NoFilePath",
			fields: fields{
				Program:      models.BPFProgram{},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
				hostConfig: &config.Config{
					BPFLogDir: "",
				},
			},
			wantErr: true,
		},
		{name: "AnyBinary",
			mockDaemon: true,
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "data.tar.gz",
					CmdStart:          GetTestExecutableName(),
					CmdStop:           GetTestExecutableName(),
					UserProgramDaemon: true,
					AdminStatus:       "enabled",
				},
				Cmd:          nil,
				FilePath:     GetTestExecutablePath(),
				RestartCount: 0,
				hostConfig: &config.Config{
					BPFLogDir: "",
				},
			},
			wantErr: false,
		},
		{name: "UserProgramFalse",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "data.tar.gz",
					CmdStart:          GetTestExecutableName(),
					CmdStop:           GetTestExecutableName(),
					UserProgramDaemon: false,
					AdminStatus:       "enabled",
				},
				Cmd:          fakeExecCommand(GetTestExecutablePathName()),
				FilePath:     GetTestExecutablePath(),
				RestartCount: 0,
				hostConfig: &config.Config{
					BPFLogDir: "",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockDaemon {
				execCommand = fakeExecCommandDaemon
				defer func() { execCommand = exec.Command }()
			}
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
				HostConfig:   tt.fields.hostConfig,
			}
			if err := b.Start(tt.fields.ifaceName, "", models.IngressType, true); (err != nil) != tt.wantErr {
				t.Errorf("BPF.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBPF_isRunning(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		CmdStatus    string
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
	}{
		{
			name: "NoPID",
			fields: fields{
				Program:      models.BPFProgram{},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}
			userProg, bpfProg, err := b.isRunning()
			if (err != nil) != tt.wantErr && (userProg == tt.want || bpfProg != tt.want) {
				t.Errorf("BPF.isRunning() user prog = %v, bpf prog = %v, error = %v, wantErr %v ", userProg, bpfProg, err, tt.wantErr)
			}
		})
	}
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}
func TestBPF_GetArtifacts(t *testing.T) {

	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		Client       *http.Client
	}
	type args struct {
		conf *config.Config
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{name: "EmptyArtifact",
			fields: fields{
				Program:      models.BPFProgram{},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			args:    args{conf: &config.Config{BPFDir: "/tmp"}},
			wantErr: true,
		},
		{name: "DummyArtifact",
			fields: fields{
				Program: models.BPFProgram{
					Name:     "dummy",
					Version:  "1",
					Artifact: "dummy.tar.gz",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
				Client: NewTestClient(func(r *http.Request) *http.Response {
					buf := new(bytes.Buffer)
					writer := gzip.NewWriter(buf)
					defer writer.Close()
					tarWriter := tar.NewWriter(writer)
					defer tarWriter.Close()
					header := new(tar.Header)
					header.Name = "random"
					header.Mode = 0777
					tarWriter.WriteHeader(header)
					tarWriter.Write([]byte("random things"))
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(buf),
						Header:     make(http.Header),
					}
				}),
			},
			args: args{conf: &config.Config{BPFDir: "/tmp",
				EBPFRepoURL: "https://l3af.io/"}},
			wantErr: true,
		},
		{
			name: "Unknown_url_with_http_scheme",
			fields: fields{
				Program: models.BPFProgram{
					EPRURL: "http://www.example.com",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			args: args{
				conf: &config.Config{
					BPFDir:      "/tmp",
					EBPFRepoURL: "https://l3af.io/",
				},
			},
			wantErr: true,
		},
		{
			name: "Unknown_url_with_file_scheme",
			fields: fields{
				Program: models.BPFProgram{
					EPRURL: "file:///Users/random/dummy.tar.gz",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			args: args{
				conf: &config.Config{
					BPFDir:      "/tmp",
					EBPFRepoURL: "https://l3af.io/",
				},
			},
			wantErr: true,
		},
		{
			name: "Unknown_scheme",
			fields: fields{
				Program: models.BPFProgram{
					EPRURL: "ftp://ftp.foo.org/dummy.tar.gz",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			args: args{
				conf: &config.Config{
					BPFDir:      "/tmp",
					EBPFRepoURL: "https://l3af.io/",
				},
			},
			wantErr: true,
		},
		{
			name: "ZipReaderFail",
			fields: fields{
				Program: models.BPFProgram{
					Name:     "testebpfprogram",
					Version:  "1.0",
					Artifact: "testebpfprogram.zip",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
				Client: NewTestClient(func(r *http.Request) *http.Response {
					buf := new(bytes.Buffer)
					writer := zip.NewWriter(buf)
					f, _ := writer.Create("testebpfprogram")
					data := strings.NewReader("this is just a test ebpf program")
					io.Copy(f, data)
					writer.Close()
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(buf),
						Header:     make(http.Header),
					}
				}),
			},
			args: args{
				conf: &config.Config{
					BPFDir: "/tmp",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := mocks.NewMockplatformInterface(ctrl)
			if runtime.GOOS == "windows" {
				m.EXPECT().GetPlatform().Return("windows", nil).AnyTimes()
			} else {
				m.EXPECT().GetPlatform().Return("focal", nil).AnyTimes()
			}
			err := b.GetArtifacts(tt.args.conf)
			if (err != nil) != tt.wantErr {
				t.Errorf("BPF.download() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBPF_SetPrLimits(t *testing.T) {
	type fields struct {
		Program models.BPFProgram
		Cmd     *exec.Cmd
		//		Pid          int
		FilePath     string
		RestartCount int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{name: "DefaultLimitsWithNoCmd",
			fields: fields{
				Program:      models.BPFProgram{},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			wantErr: true,
		},
		{name: "ValidLimitsWithNoCmd",
			fields: fields{
				Program: models.BPFProgram{
					CPU:    100,
					Memory: 1024,
				},
				Cmd:          fakeExecCommand("/foo/foo"),
				FilePath:     "",
				RestartCount: 0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program: tt.fields.Program,
				Cmd:     tt.fields.Cmd,
				//				Pid:          tt.fields.Pid,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}
			if err := b.SetPrLimits(); (err != nil) != tt.wantErr {
				t.Errorf("BPF.SetPrLimits() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_assertExecute(t *testing.T) {
	type args struct {
		filepath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "InvalidFilepath",
			args: args{
				filepath: "/tmp/dummyfile",
			},
			wantErr: true,
		},
		{
			name: "ValidFilepath",
			args: args{
				filepath: GetTestExecutablePathName(),
			},
			wantErr: false,
		},
		{
			name: "ValidFilepathWihoutExecute",
			args: args{
				filepath: GetTestNonexecutablePathName(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := assertExecutable(tt.args.filepath); (err != nil) != tt.wantErr {
				t.Errorf("assertExecute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_fileExists(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		exist    bool
	}{
		{
			name:     "invalidfilename",
			fileName: "blahblah",
			exist:    false,
		},
	}
	for _, tt := range tests {
		if fileExists(tt.fileName) != tt.exist {
			t.Errorf("Invalid filename")
		}
	}
}

func Test_StopExternalRunningProcess(t *testing.T) {
	tests := []struct {
		name        string
		processName string
		wantErr     bool
	}{
		{
			name:        "emptyProcessName",
			processName: "",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		err := StopExternalRunningProcess(tt.processName)
		if (err != nil) != tt.wantErr {
			t.Errorf("Error During execution StopExternalRunningProcess : %v", err)
		}
	}
}

func Test_createUpdateRulesFile(t *testing.T) {
	type fields struct {
		Program models.BPFProgram
		Cmd     *exec.Cmd
		//		Pid          int
		FilePath     string
		RestartCount int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "emptyRuleFileName",
			fields: fields{
				Program: models.BPFProgram{
					RulesFile: "",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			wantErr: true,
		},
		{
			name: "invalidPath",
			fields: fields{
				Program: models.BPFProgram{
					RulesFile: "bad",
				},
				Cmd:          nil,
				FilePath:     "/dummy/fpp",
				RestartCount: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}
			_, err := b.createUpdateRulesFile("ingress")
			if (err != nil) != tt.wantErr {
				t.Errorf("createUpdateRulesFile() error : %v", err)
			}
		})
	}
}

func Test_PutNextProgFDFromID(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		hostConfig   *config.Config
	}
	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		progId     int
		hostConfig *config.Config
	}{
		{
			name: "emptyMapName",
			fields: fields{
				Program: models.BPFProgram{
					MapName: "",
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			wantErr: false,
			progId:  1,
		},
		{
			name: "invalidMapName",
			fields: fields{
				Program: models.BPFProgram{
					MapName: "invalidname",
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			wantErr: true,
			progId:  1,
		},
		{
			name: "invalidProgID",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "ratelimiting",
					SeqID:             1,
					Artifact:          "l3af_ratelimiting.tar.gz",
					MapName:           "xdp_rl_ingress_next_prog",
					CmdStart:          "ratelimiting",
					Version:           "latest",
					UserProgramDaemon: true,
					AdminStatus:       "enabled",
					ProgType:          "xdp",
					CfgVersion:        1,
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			progId:  -1,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
				HostConfig:   tt.fields.hostConfig,
			}
			err := b.PutNextProgFDFromID(tt.progId)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutNextProgFDFromID() error : %v", err)
			}
		})
	}
}

func Test_VerifyPinnedProgMapExists(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		hostConfig   *config.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "invalidMapName",
			fields: fields{
				Program: models.BPFProgram{
					MapName: "invalid",
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
				HostConfig:   tt.fields.hostConfig,
			}
			err := b.VerifyPinnedProgMap(true, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPinnedMapExists() error : %v", err)
			}
		})
	}
}
func Test_VerifyProcessObject(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "nilCmd",
			fields: fields{
				Program:      models.BPFProgram{},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			wantErr: true,
		},
		{
			name: "nillCmdProcess",
			fields: fields{
				Program: models.BPFProgram{},
				Cmd: &exec.Cmd{
					Process: nil,
				},
				FilePath:     "",
				RestartCount: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
			}
			err := b.VerifyProcessObject()
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyProcessObject() error : %v", err)
			}
		})
	}
}

func Test_VerifyPinnedProgMapVanish(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
		hostConfig   *config.Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "emptyMapName",
			fields: fields{
				Program: models.BPFProgram{
					MapName: "",
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			wantErr: false,
		},
		{
			name: "invalidProgType",
			fields: fields{
				Program: models.BPFProgram{
					MapName:  "tc/globals/something",
					ProgType: models.TCType,
				},
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
				HostConfig: &config.Config{
					BpfMapDefaultPath: tt.fields.hostConfig.BpfMapDefaultPath,
				},
			}
			err := b.VerifyPinnedProgMap(true, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPinnedMapVanish() error : %v", err)
			}
		})
	}
}

func TestBPF_IsLoaded(t *testing.T) {
	tests := []struct {
		name   string
		progID uint32
		want   bool
	}{
		{
			name:   "ZeroProgID",
			progID: 0,
			want:   false,
		},
		{
			// A non-zero ID that doesn't correspond to any program loaded in
			// the kernel: ebpf.NewProgramFromID fails and IsLoaded reports
			// false without ever reaching the interface-attachment check.
			name:   "InvalidNonZeroProgID",
			progID: 0x7fffffff,
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{Program: models.BPFProgram{Name: "testprog"}}
			b.ProgID.Store(tt.progID)
			if got := b.IsLoaded(); got != tt.want {
				t.Errorf("BPF.IsLoaded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_ifindexMatches exercises the pure ifindex-vs-interface comparison
// that backs isAttachedToInterface's XDP/TCX mismatch detection, using the
// real "lo" loopback interface (present on every host) as a stable,
// non-privileged source of a genuine ifindex - no kernel eBPF calls
// required.
func Test_ifindexMatches(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface available on this host")
	}

	tests := []struct {
		name        string
		linkIfindex uint32
		ifaceName   string
		want        bool
	}{
		{
			name:        "MatchingIfindex",
			linkIfindex: uint32(lo.Index),
			ifaceName:   "lo",
			want:        true,
		},
		{
			name:        "DriftedIfindex",
			linkIfindex: uint32(lo.Index) + 1000,
			ifaceName:   "lo",
			want:        false,
		},
		{
			name:        "UnknownInterfaceName",
			linkIfindex: uint32(lo.Index),
			ifaceName:   "nosuchif0",
			want:        false,
		},
		{
			name:        "ZeroIfindexTreatedAsUnknown",
			linkIfindex: 0,
			ifaceName:   "nosuchif0",
			want:        true,
		},
		{
			// Same zero-ifindex guard, but paired with a real interface name
			// that would otherwise resolve and compare fine. This fails loudly
			// if the zero-check is ever reordered to run after the
			// net.InterfaceByName lookup instead of before it.
			name:        "ZeroIfindexTreatedAsUnknownEvenWithValidIface",
			linkIfindex: 0,
			ifaceName:   "lo",
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ifindexMatches(tt.linkIfindex, tt.ifaceName); got != tt.want {
				t.Errorf("ifindexMatches(%d, %q) = %v, want %v", tt.linkIfindex, tt.ifaceName, got, tt.want)
			}
		})
	}
}

// Test_isAttachedToInterface covers the short-circuit paths of the
// interface-attachment check used by IsLoaded. Programs without a
// link-based attachment (b.Link == nil - classic TC filters, chained or
// user-daemon programs) or without a recorded IfaceName must never be
// reported as "not attached", regardless of the value of the other field.
//
// Exercising the XDP/TCX mismatch branches themselves (info.XDP()/
// info.TCX(), i.e. going through a real link.Link) needs a kernel-backed
// link, which isn't obtainable in this unit test environment; that part of
// the dispatch is covered indirectly by Test_ifindexMatches above and
// needs to be verified end-to-end on a Linux host with eBPF support.
func Test_isAttachedToInterface(t *testing.T) {
	tests := []struct {
		name      string
		link      link.Link
		ifaceName string
		want      bool
	}{
		{
			name:      "NilLinkWithIfaceName",
			link:      nil,
			ifaceName: "eth0",
			want:      true,
		},
		{
			name:      "NilLinkNoIfaceName",
			link:      nil,
			ifaceName: "",
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BPF{
				Program:   models.BPFProgram{Name: "testprog"},
				Link:      tt.link,
				IfaceName: tt.ifaceName,
			}
			if got := b.isAttachedToInterface(); got != tt.want {
				t.Errorf("BPF.isAttachedToInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBPF_Start_SetsIfaceName verifies that Start records the interface it
// was asked to attach to, since IsLoaded's interface-attachment check
// depends on b.IfaceName being populated.
func TestBPF_Start_SetsIfaceName(t *testing.T) {
	b := &BPF{
		Program: models.BPFProgram{
			Name:        "nfprogram",
			AdminStatus: "enabled",
		},
		FilePath:   GetTestExecutablePath(),
		HostConfig: &config.Config{},
	}
	// No ObjectFile/CmdStart is set, so Start skips the real attach/exec
	// paths; isRunning -> IsLoaded sees ProgID 0 and b.Link == nil, both of
	// which short-circuit to "not attached" without touching the kernel, so
	// this can't false-negative on the feature under test.
	if err := b.Start("eth7", "", models.IngressType, true); err != nil {
		t.Fatalf("BPF.Start() unexpected error = %v", err)
	}
	if b.IfaceName != "eth7" {
		t.Errorf("BPF.Start() IfaceName = %q, want %q", b.IfaceName, "eth7")
	}
}
