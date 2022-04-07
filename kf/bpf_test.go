// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/l3af-project/l3afd/config"
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
				LogDir:         "",
				BpfMaps:        make(map[string]BPFMap, 0),
				MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
				Ctx:            nil,
				Done:           nil,
				DataCenter:     "localdc",
			},
		},
		{name: "EmptyBPFProgram",
			args: args{
				program: models.BPFProgram{},
				logDir:  "",
			},
			want: &BPF{
				Program:        models.BPFProgram{},
				Cmd:            nil,
				FilePath:       "",
				BpfMaps:        make(map[string]BPFMap, 0),
				MetricsBpfMaps: make(map[string]*MetricsBPFMap, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewBpfProgram(tt.args.ctx, tt.args.program, tt.args.logDir, tt.args.datacenter); !reflect.DeepEqual(got, tt.want) {
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
		ctx          context.Context
		datacenter   string
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
		seqID        int
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

func TestBPF_GetArtifacts(t *testing.T) {
	type fields struct {
		Program      models.BPFProgram
		Cmd          *exec.Cmd
		FilePath     string
		RestartCount int
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
					Artifact: "dummy.tar.gz",
				},
				Cmd:          nil,
				FilePath:     "",
				RestartCount: 0,
			},
			args: args{conf: &config.Config{BPFDir: "/tmp",
				KFRepoURL: "http://www.example.com"}},
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
			if err := b.GetArtifacts(tt.args.conf); (err != nil) != tt.wantErr {
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
