// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"container/list"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"

	"github.com/rs/zerolog/log"
)

var (
	machineHostname string
	HostInterfaces  map[string]bool
	pMon            *PCheck
	mMon            *BpfMetrics
	valVerChange    *models.BPFPrograms
	valStatusChange *models.BPFPrograms
	ingressXDPBpfs  map[string]*list.List
	ingressTCBpfs   map[string]*list.List
	egressTCBpfs    map[string]*list.List
	ifaceName       string
	seqID           int
	bpfProgs        *models.BPFPrograms
)

func setupDBTest() {
	machineHostname, _ = os.Hostname()
	HostInterfaces = make(map[string]bool)
	HostInterfaces["fakeif0"] = true
	pMon = NewPCheck(3, true, 10)
	mMon = NewpBpfMetrics(true, 30)

	ingressXDPBpfs = make(map[string]*list.List)
	ingressTCBpfs = make(map[string]*list.List)
	egressTCBpfs = make(map[string]*list.List)
}

func setupValidBPF() {
	bpf := BPF{
		Program: models.BPFProgram{
			ID:                1,
			Name:              "foo",
			Artifact:          "foo.tar.gz",
			CmdStart:          "foo",
			CmdStop:           "",
			Version:           "1.0",
			UserProgramDaemon: true,
			AdminStatus:       "DISABLED",
		},
		Cmd:          nil,
		FilePath:     "",
		RestartCount: 0,
	}
	ifaceName = "dummy"
	seqID = 1
	log.Info().Msg(bpf.Program.Name)
}

func setupBPFProgramData() {
	bpfProgsTmp := &models.BPFPrograms{}
	ifaceName = "dummy"
	seqID = 1

	bpfProg := &models.BPFProgram{
		ID:                1,
		Name:              "foo",
		Artifact:          "foo.tar.gz",
		CmdStart:          "foo",
		CmdStop:           "",
		Version:           "1.0",
		UserProgramDaemon: true,
		AdminStatus:       "ENABLED",
		SeqID:             1,
	}
	bpfProgsTmp.XDPIngress = append(bpfProgsTmp.XDPIngress, bpfProg)

	bpfProgs = bpfProgsTmp
}

func setupBPFProgramVersionChange() {
	bpfProgsTmp := &models.BPFPrograms{}
	ifaceName = "dummy"
	seqID = 1

	bpfProg := &models.BPFProgram{
		ID:                1,
		Name:              "foo",
		Artifact:          "foo.tar.gz",
		CmdStart:          "foo",
		CmdStop:           "",
		Version:           "2.0",
		UserProgramDaemon: true,
		AdminStatus:       "ENABLED",
	}
	bpfProgsTmp.XDPIngress = append(bpfProgsTmp.XDPIngress, bpfProg)
	valVerChange = bpfProgsTmp
}

func setupBPFProgramStatusChange() {

	bpfProgsTmp := &models.BPFPrograms{}
	//cfg := make(map[string][]*models.BPFProgram)
	ifaceName = "dummy"
	seqID = 1

	bpfProg := &models.BPFProgram{
		ID:                1,
		Name:              "foo",
		Artifact:          "foo.tar.gz",
		CmdStart:          "foo",
		CmdStop:           "",
		Version:           "2.0",
		UserProgramDaemon: true,
		AdminStatus:       "DISABLED",
	}
	bpfProgsTmp.XDPIngress = append(bpfProgsTmp.XDPIngress, bpfProg)
	valStatusChange = bpfProgsTmp
}

func TestNewNFConfigs(t *testing.T) {
	type args struct {
		host     string
		hostConf *config.Config
		pMon     *PCheck
		mMon     *BpfMetrics
		ctx      context.Context
	}
	setupDBTest()
	hostIfaces, _ := getHostInterfaces()
	tests := []struct {
		name    string
		args    args
		want    *NFConfigs
		wantErr bool
	}{
		{name: "EmptyConfig",
			args: args{
				host:     machineHostname,
				hostConf: nil,
				pMon:     pMon,
				mMon:     mMon},
			want: &NFConfigs{HostName: machineHostname,
				HostInterfaces: hostIfaces,
				IngressXDPBpfs: ingressXDPBpfs,
				IngressTCBpfs:  ingressTCBpfs,
				EgressTCBpfs:   egressTCBpfs,
				HostConfig:     nil,
				ProcessMon:     pMon,
				BpfMetricsMon:  mMon,
				Mu:             new(sync.Mutex),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewNFConfigs(tt.args.ctx, tt.args.host, tt.args.hostConf, tt.args.pMon, tt.args.mMon)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNFConfigs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewNFConfigs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNFConfigs_Deploy(t *testing.T) {
	type fields struct {
		hostName       string
		HostInterfaces map[string]bool
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
		metricsMon     *BpfMetrics
	}
	type args struct {
		iface    string
		hostName string
		bpfProgs *models.BPFPrograms
	}

	setupDBTest()
	setupValidBPF()
	setupBPFProgramData()
	setupBPFProgramVersionChange()
	setupBPFProgramStatusChange()

	HostInterfaces, err := getHostInterfaces()
	if err != nil {
		log.Info().Msg("getHostInterfaces returned and error")
	}
	var HostInterfacesKey string
	var HostInterfacesValue bool
	for HostInterfacesKey, HostInterfacesValue = range HostInterfaces {
		log.Debug().Msgf("HostInterfacesKey: %v, HostInterfacesValue: %v", HostInterfacesKey, HostInterfacesValue)
		break
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "EmptyBPFs",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    "",
				hostName: machineHostname,
				bpfProgs: nil,
			},
			wantErr: true,
		},
		{
			name: "InvalidHostName",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    "dummy",
				hostName: "dummy",
				bpfProgs: bpfProgs,
			},
			wantErr: true,
		},
		{
			name: "ValidHostNameInvalidIfaceName",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    "dummy",
				hostName: machineHostname,
				bpfProgs: &models.BPFPrograms{},
			},
			wantErr: true,
		},
		{
			name: "ValidHostNameValidIfaceName",
			fields: fields{
				hostName:       machineHostname,
				HostInterfaces: HostInterfaces,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    HostInterfacesKey,
				hostName: machineHostname,
				bpfProgs: &models.BPFPrograms{},
			},
			wantErr: false,
		},
		{
			name: "TestEBPFRepoDownload",
			fields: fields{
				hostName:       machineHostname,
				HostInterfaces: HostInterfaces,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", EBPFRepoURL: "http://www.example.com"},
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    HostInterfacesKey,
				hostName: machineHostname,
				bpfProgs: bpfProgs,
			},
			wantErr: false,
		},
		{
			name: "NewBPFWithVersionChange",
			fields: fields{
				hostName:       machineHostname,
				HostInterfaces: HostInterfaces,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", EBPFRepoURL: "http://www.example.com"},
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    HostInterfacesKey,
				hostName: machineHostname,
				bpfProgs: valVerChange,
			},
			wantErr: false,
		},
		{
			name: "NewBPFWithStatusChange",
			fields: fields{
				hostName:       machineHostname,
				HostInterfaces: HostInterfaces,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", EBPFRepoURL: "http://www.example.com"},
				ProcessMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				iface:    HostInterfacesKey,
				hostName: machineHostname,
				bpfProgs: valStatusChange,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName: tt.fields.hostName,
				//				configs:    tt.fields.configs,
				HostInterfaces: tt.fields.HostInterfaces,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				HostConfig:     tt.fields.hostConfig,
				ProcessMon:     tt.fields.ProcessMon,
				Mu:             new(sync.Mutex),
			}
			if err := cfg.Deploy(tt.args.iface, tt.args.hostName, tt.args.bpfProgs); (err != nil) != tt.wantErr {
				t.Errorf("NFConfigs.Deploy() error = %#v, wantErr %#v", err, tt.wantErr)
			}
		})
	}
}

func TestNFConfigs_Close(t *testing.T) {
	type fields struct {
		hostName       string
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "EmptyMap",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig: &config.Config{
					BpfMapDefaultPath: "/sys/fs/bpf",
					ShutdownTimeout:   30 * time.Second,
				},
				ProcessMon: pMon,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName:       tt.fields.hostName,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				HostConfig:     tt.fields.hostConfig,
				ProcessMon:     tt.fields.ProcessMon,
			}
			ctx, cancelfunc := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelfunc()
			if err := cfg.Close(ctx); (err != nil) != tt.wantErr {
				t.Errorf("NFConfigs.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getHostInterfaces(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "GoodInput",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getHostInterfaces()
			if (err != nil) != tt.wantErr {
				t.Errorf("getHostInterfaces() error : %v", err)
			}
		})
	}
}
func Test_BinarySearch(t *testing.T) {
	tests := []struct {
		name   string
		vals   []string
		target string
		result bool
	}{
		{
			name:   "FoundTheTarget",
			vals:   []string{"connection-limit", "ipfix-flow-exporter", "ratelimiting"},
			target: "ratelimiting",
			result: true,
		},
		{
			name:   "DidNotFindTheTarget",
			vals:   []string{"connection-limit", "ipfix-flow-exporter", "ratelimiting"},
			target: "zsdf",
			result: false,
		},
	}

	for _, tt := range tests {
		if BinarySearch(tt.vals, tt.target) != tt.result {
			t.Errorf("BinarySearch is not producing expected output")
		}
	}
}

func Test_AddProgramsOnInterface(t *testing.T) {
	HostInterfaces, err := getHostInterfaces()
	if err != nil {
		log.Info().Msg("getHostInterfaces returned and error")
	}
	var HostInterfacesKey string
	var HostInterfacesValue bool
	for HostInterfacesKey, HostInterfacesValue = range HostInterfaces {
		log.Debug().Msgf("HostInterfacesKey: %v, HostInterfacesValue: %v", HostInterfacesKey, HostInterfacesValue)
		break
	}
	type fields struct {
		hostName       string
		HostInterfaces map[string]bool
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
		mu             *sync.Mutex
	}
	type args struct {
		iface    string
		hostName string
		bpfProgs *models.BPFPrograms
	}
	tests := []struct {
		name    string
		field   fields
		arg     args
		wanterr bool
	}{
		{
			name:    "UnknownHostName",
			field:   fields{},
			arg:     args{},
			wanterr: true,
		},
		{
			name: "NilInterface",
			field: fields{
				hostName: "l3af-local-test",
			},
			arg: args{
				hostName: "fakeif0",
			},
			wanterr: true,
		},
		{
			name: "UnknownInterface",
			field: fields{
				hostName: "l3af-local-test",
			},
			arg: args{
				hostName: "l3af-local-test",
				iface:    "dummyinterface",
				bpfProgs: &models.BPFPrograms{
					XDPIngress: []*models.BPFProgram{
						&models.BPFProgram{
							Name:              "dummy_name",
							SeqID:             1,
							Artifact:          "dummy_artifact.tar.gz",
							MapName:           "xdp_rl_ingress_next_prog",
							CmdStart:          "dummy_command",
							Version:           "latest",
							UserProgramDaemon: true,
							AdminStatus:       "enabled",
							ProgType:          "xdp",
							CfgVersion:        1,
						},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "GoodInput",
			field: fields{
				hostName:       "l3af-local-test",
				HostInterfaces: HostInterfaces,
				mu:             new(sync.Mutex),
				ingressXDPBpfs: map[string]*list.List{"fakeif0": nil},
				ingressTCBpfs:  map[string]*list.List{"fakeif0": nil},
				egressTCBpfs:   map[string]*list.List{"fakeif0": nil},
				hostConfig: &config.Config{
					BpfChainingEnabled: true,
				},
			},
			arg: args{
				hostName: "l3af-local-test",
				iface:    HostInterfacesKey,
				bpfProgs: &models.BPFPrograms{
					XDPIngress: []*models.BPFProgram{},
					TCEgress:   []*models.BPFProgram{},
					TCIngress:  []*models.BPFProgram{},
				},
			},
			wanterr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName:       tt.field.hostName,
				IngressXDPBpfs: tt.field.ingressXDPBpfs,
				IngressTCBpfs:  tt.field.ingressTCBpfs,
				EgressTCBpfs:   tt.field.egressTCBpfs,
				HostConfig:     tt.field.hostConfig,
				ProcessMon:     tt.field.ProcessMon,
				HostInterfaces: tt.field.HostInterfaces,
				Mu:             tt.field.mu,
			}
			err := cfg.AddProgramsOnInterface(tt.arg.iface, tt.arg.hostName, tt.arg.bpfProgs)
			if (err != nil) != tt.wanterr {
				t.Errorf("AddProgramsOnInterface: %v", err)
			}
		})
	}
}

func TestAddeBPFPrograms(t *testing.T) {
	HostInterfaces, err := getHostInterfaces()
	if err != nil {
		log.Info().Msg("getHostInterfaces returned and error")
	}
	var HostInterfacesKey string
	var HostInterfacesValue bool
	for HostInterfacesKey, HostInterfacesValue = range HostInterfaces {
		log.Debug().Msgf("HostInterfacesKey: %v, HostInterfacesValue: %v", HostInterfacesKey, HostInterfacesValue)
		break
	}
	type fields struct {
		hostName       string
		HostInterfaces map[string]bool
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
		mu             *sync.Mutex
		ifaces         map[string]string
	}
	tests := []struct {
		name    string
		field   fields
		arg     []models.L3afBPFPrograms
		wanterr bool
	}{
		{
			name: "UnknownHostName",
			field: fields{
				hostName: "l3af-prod",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFPrograms{
				{
					HostName: "l3af-test",
					Iface:    "fakeif0",
					BpfPrograms: &models.BPFPrograms{
						XDPIngress: []*models.BPFProgram{},
						TCIngress:  []*models.BPFProgram{},
						TCEgress:   []*models.BPFProgram{},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "NilInterface",
			field: fields{
				hostName: "l3af-local-test",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFPrograms{
				{
					HostName: "l3af-local-test",
					BpfPrograms: &models.BPFPrograms{
						XDPIngress: []*models.BPFProgram{},
						TCIngress:  []*models.BPFProgram{},
						TCEgress:   []*models.BPFProgram{},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "UnknownInterface",
			field: fields{
				hostName: "l3af-local-test",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFPrograms{
				{
					HostName: "l3af-local-test",
					Iface:    "dummyinterface",
					BpfPrograms: &models.BPFPrograms{
						XDPIngress: []*models.BPFProgram{
							&models.BPFProgram{
								Name:              "dummy_name",
								SeqID:             1,
								Artifact:          "dummy_artifact_name",
								MapName:           "xdp_rl_ingress_next_prog",
								CmdStart:          "dummy_command",
								Version:           "latest",
								UserProgramDaemon: true,
								AdminStatus:       "enabled",
								ProgType:          "xdp",
								CfgVersion:        1,
							},
						},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "GoodInput",
			field: fields{
				hostName:       "l3af-local-test",
				HostInterfaces: HostInterfaces,
				// fakeif0 is a fake interface
				mu:             new(sync.Mutex),
				ingressXDPBpfs: map[string]*list.List{"fakeif0": nil},
				ingressTCBpfs:  map[string]*list.List{"fakeif0": nil},
				egressTCBpfs:   map[string]*list.List{"fakeif0": nil},
				ifaces:         map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFPrograms{
				{
					HostName: "l3af-local-test",
					Iface:    HostInterfacesKey,
					BpfPrograms: &models.BPFPrograms{
						XDPIngress: []*models.BPFProgram{},
						TCIngress:  []*models.BPFProgram{},
						TCEgress:   []*models.BPFProgram{},
					},
				},
			},
			wanterr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName:       tt.field.hostName,
				IngressXDPBpfs: tt.field.ingressXDPBpfs,
				IngressTCBpfs:  tt.field.ingressTCBpfs,
				EgressTCBpfs:   tt.field.egressTCBpfs,
				HostConfig:     tt.field.hostConfig,
				ProcessMon:     tt.field.ProcessMon,
				HostInterfaces: tt.field.HostInterfaces,
				Mu:             tt.field.mu,
			}
			err := cfg.AddeBPFPrograms(tt.arg)
			if (err != nil) != tt.wanterr {
				t.Errorf("AddeBPFPrograms failed: %v", err)
			}
		})
	}
}

func TestDeleteProgramsOnInterface(t *testing.T) {
	type fields struct {
		hostName       string
		HostInterfaces map[string]bool
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
		mu             *sync.Mutex
	}
	type args struct {
		iface    string
		hostName string
		bpfProgs *models.BPFProgramNames
	}
	tests := []struct {
		name    string
		field   fields
		arg     args
		wanterr bool
	}{
		{
			name:    "UnknownHostName",
			field:   fields{},
			arg:     args{},
			wanterr: true,
		},
		{
			name: "NilInterface",
			field: fields{
				hostName: "l3af-local-test",
			},
			arg: args{
				hostName: "fakeif0",
			},
			wanterr: true,
		},
		{
			name: "UnknownInterface",
			field: fields{
				hostName: "l3af-local-test",
			},
			arg: args{
				hostName: "l3af-local-test",
				iface:    "dummyinterface",
				bpfProgs: &models.BPFProgramNames{
					XDPIngress: []string{},
					TCIngress:  []string{},
					TCEgress:   []string{},
				},
			},
			wanterr: true,
		},
		{
			name: "GoodInputButNotRealInterface",
			field: fields{
				hostName:       "l3af-local-test",
				HostInterfaces: map[string]bool{"fakeif0": true},
				mu:             new(sync.Mutex),
				ingressXDPBpfs: map[string]*list.List{"fakeif0": nil},
				ingressTCBpfs:  map[string]*list.List{"fakeif0": nil},
				egressTCBpfs:   map[string]*list.List{"fakeif0": nil},
			},
			arg: args{
				hostName: "l3af-local-test",
				iface:    "fakeif0",
				bpfProgs: &models.BPFProgramNames{
					XDPIngress: []string{},
					TCIngress:  []string{},
					TCEgress:   []string{},
				},
			},
			wanterr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName:       tt.field.hostName,
				IngressXDPBpfs: tt.field.ingressXDPBpfs,
				IngressTCBpfs:  tt.field.ingressTCBpfs,
				EgressTCBpfs:   tt.field.egressTCBpfs,
				HostConfig:     tt.field.hostConfig,
				ProcessMon:     tt.field.ProcessMon,
				HostInterfaces: tt.field.HostInterfaces,
				Mu:             tt.field.mu,
			}
			err := cfg.DeleteProgramsOnInterface(tt.arg.iface, tt.arg.hostName, tt.arg.bpfProgs)
			if (err != nil) != tt.wanterr {
				t.Errorf("DeleteProgramsOnInterface failed: %v", err)
			}
		})
	}
}

func TestDeleteEbpfPrograms(t *testing.T) {
	type fields struct {
		hostName       string
		HostInterfaces map[string]bool
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		ProcessMon     *PCheck
		mu             *sync.Mutex
		ifaces         map[string]string
	}
	tests := []struct {
		name    string
		field   fields
		arg     []models.L3afBPFProgramNames
		wanterr bool
	}{
		{
			name: "UnknowhostName",
			field: fields{
				hostName: "l3af-prod",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFProgramNames{
				{
					HostName: "l3af-local-test",
					Iface:    "fakeif0",
					BpfProgramNames: &models.BPFProgramNames{
						XDPIngress: []string{},
						TCIngress:  []string{},
						TCEgress:   []string{},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "NilInterface",
			field: fields{
				hostName: "l3af-local-test",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFProgramNames{
				{
					HostName: "l3af-local-test",
					Iface:    "fakeif0",
					BpfProgramNames: &models.BPFProgramNames{
						XDPIngress: []string{},
						TCIngress:  []string{},
						TCEgress:   []string{},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "UnknownInterface",
			field: fields{
				hostName: "l3af-local-test",
				ifaces:   map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFProgramNames{
				{
					HostName: "l3af-local-test",
					Iface:    "fakeif0",
					BpfProgramNames: &models.BPFProgramNames{
						XDPIngress: []string{},
						TCIngress:  []string{},
						TCEgress:   []string{},
					},
				},
			},
			wanterr: true,
		},
		{
			name: "GoodInputButNotRealInterface",
			field: fields{
				hostName:       "l3af-local-test",
				HostInterfaces: map[string]bool{"fakeif0": true},
				mu:             new(sync.Mutex),
				ingressXDPBpfs: map[string]*list.List{"fakeif0": nil},
				ingressTCBpfs:  map[string]*list.List{"fakeif0": nil},
				egressTCBpfs:   map[string]*list.List{"fakeif0": nil},
				ifaces:         map[string]string{},
				hostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../testdata/Test_l3af-config.json"),
				},
			},
			arg: []models.L3afBPFProgramNames{
				{
					HostName: "l3af-local-test",
					Iface:    "fakeif0",
					BpfProgramNames: &models.BPFProgramNames{
						XDPIngress: []string{},
						TCIngress:  []string{},
						TCEgress:   []string{},
					},
				},
			},
			wanterr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostName:       tt.field.hostName,
				IngressXDPBpfs: tt.field.ingressXDPBpfs,
				IngressTCBpfs:  tt.field.ingressTCBpfs,
				EgressTCBpfs:   tt.field.egressTCBpfs,
				HostConfig:     tt.field.hostConfig,
				ProcessMon:     tt.field.ProcessMon,
				HostInterfaces: tt.field.HostInterfaces,
				Mu:             tt.field.mu,
			}
			err := cfg.DeleteEbpfPrograms(tt.arg)
			if (err != nil) != tt.wanterr {
				t.Errorf("DeleteEbpfPrograms failed: %v", err)
			}
		})
	}
}

func TestAddAndStartBPF(t *testing.T) {
	type field struct {
		ctx        context.Context
		hostConfig *config.Config
	}
	type arg struct {
		bpfProg   *models.BPFProgram
		direction string
		iface     string
	}
	tests := []struct {
		name    string
		fields  field
		args    arg
		wanterr bool
	}{
		{
			name:   "NilProgram",
			fields: field{},
			args: arg{
				bpfProg:   nil,
				direction: "fakedirection",
				iface:     "fakeif0",
			},
			wanterr: true,
		},
		{
			name:   "AdminStatusDisabled",
			fields: field{},
			args: arg{
				bpfProg: &models.BPFProgram{
					Name:        "dummy",
					AdminStatus: "disabled",
				},
				direction: "fakedirection",
				iface:     "fakeif0",
			},
			wanterr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				Ctx:        tt.fields.ctx,
				HostConfig: tt.fields.hostConfig,
			}
			e := cfg.AddAndStartBPF(tt.args.bpfProg, tt.args.iface, tt.args.direction)
			if (e != nil) != tt.wanterr {
				t.Errorf("AddAndStartBPF failed : %v", e)
			}
		})
	}
}

func TestAddProgramWithoutChaining(t *testing.T) {
	progList := list.New()
	progList.PushBack(&BPF{
		Program: models.BPFProgram{
			Name: "dummyProgram",
		},
	})
	type fields struct {
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
	}
	type args struct {
		iface    string
		hostName string
		bpfProgs *models.BPFPrograms
	}
	tests := []struct {
		name    string
		field   fields
		arg     args
		wanterr bool
	}{
		{
			name: "chainingEnabled",
			field: fields{
				hostConfig: &config.Config{
					BpfChainingEnabled: true,
				},
			},
			arg: args{
				iface:    "fakeif0",
				hostName: "fakehost",
			},
			wanterr: false,
		},
		{
			name: "badInput",
			field: fields{
				hostConfig: &config.Config{
					BpfChainingEnabled: false,
				},
				ingressXDPBpfs: map[string]*list.List{"fakeif0": progList},
				egressTCBpfs:   map[string]*list.List{"fakeif0": progList},
				ingressTCBpfs:  map[string]*list.List{"fakeif0": progList},
			},
			arg: args{
				iface: "fakeif0",
				bpfProgs: &models.BPFPrograms{
					XDPIngress: []*models.BPFProgram{
						{
							Name:        "dummyProgram",
							AdminStatus: models.Enabled,
						},
					},
					TCIngress: []*models.BPFProgram{
						{
							Name:        "dummyProgram",
							AdminStatus: models.Enabled,
						},
					},
					TCEgress: []*models.BPFProgram{
						{
							Name:        "dummyProgram",
							AdminStatus: models.Enabled,
						},
					},
				},
			},
			wanterr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				HostConfig:     tt.field.hostConfig,
				IngressXDPBpfs: tt.field.ingressXDPBpfs,
				EgressTCBpfs:   tt.field.egressTCBpfs,
				IngressTCBpfs:  tt.field.ingressTCBpfs,
			}
			e := cfg.AddProgramWithoutChaining(tt.arg.iface, tt.arg.bpfProgs)
			if (e != nil) != tt.wanterr {
				t.Errorf(" AddProgramWithoutChaining failed : %v", e)
			}
		})
	}
}
