// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/mocks"
	"github.com/l3af-project/l3afd/models"
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

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
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
					Version:           "1.0",
					UserProgramDaemon: true,
					IsPlugin:          false,
					AdminStatus:       "enabled",
				},
				Cmd:            nil,
				FilePath:       "",
				BpfMaps:        make(map[string]BPFMap, 0),
				MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
				Ctx:            nil,
				Done:           nil,
				hostConfig: &config.Config{
					BPFLogDir:  "",
					DataCenter: "localdc",
				},
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
				hostConfig:     &config.Config{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewBpfProgram(tt.args.ctx, tt.args.program, tt.args.hostConfig); !reflect.DeepEqual(got, tt.want) {
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
					Artifact:          "ls.tar.gz",
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
			if err := b.Stop(ifaceName, models.IngressType, false); (err != nil) != tt.wantErr {
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
		name    string
		fields  fields
		wantErr bool
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
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "ls.tar.gz",
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
					Artifact:          "ls.tar.gz",
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
			wantErr: true,
		},
		{name: "withResourceLimits",
			fields: fields{
				Program: models.BPFProgram{
					Name:              "nfprogram",
					Artifact:          "ls.tar.gz",
					CmdStart:          GetTestExecutableName(),
					CmdStop:           GetTestExecutableName(),
					UserProgramDaemon: true,
					AdminStatus:       "enabled",
					CPU:               100,
					Memory:            1024,
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
			b := &BPF{
				Program:      tt.fields.Program,
				Cmd:          tt.fields.Cmd,
				FilePath:     tt.fields.FilePath,
				RestartCount: tt.fields.RestartCount,
				hostConfig:   tt.fields.hostConfig,
			}
			if err := b.Start(tt.fields.ifaceName, models.IngressType, true); (err != nil) != tt.wantErr {
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
			want:    true,
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
			got, err := b.isRunning()
			if (err != nil) != tt.wantErr {
				t.Errorf("BPF.isRunning() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BPF.isRunning() = %v, want %v", got, tt.want)
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
		Program models.BPFProgram
		Cmd     *exec.Cmd
		//		Pid          int
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
				hostConfig:   tt.fields.hostConfig,
			}
			err := b.PutNextProgFDFromID(tt.progId)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutNextProgFDFromID() error : %v", err)
			}
		})
	}
}

func Test_VerifyPinnedMapExists(t *testing.T) {
	type fields struct {
		Program models.BPFProgram
		Cmd     *exec.Cmd
		//		Pid          int
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
				hostConfig:   tt.fields.hostConfig,
			}
			err := b.VerifyPinnedMapExists(true)
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

func Test_VerifyPinnedMapVanish(t *testing.T) {
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
				hostConfig: &config.Config{
					BpfMapDefaultPath: tt.fields.hostConfig.BpfMapDefaultPath,
				},
			}
			err := b.VerifyPinnedMapVanish(true)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPinnedMapVanish() error : %v", err)
			}
		})
	}
}
