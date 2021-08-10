// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"container/list"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"tbd/admind/models"
	"tbd/cfgdist/kvstores"
	"tbd/cfgdist/kvstores/emitter"

	"tbd/l3afd/config"

	"github.com/rs/zerolog/log"
)

var (
	emit            *mockKeyChangeEmitter
	machineHostname string
	pMon            *pCheck
	mMon            *kfMetrics
	val             []byte
	valVerChange    []byte
	valStatusChange []byte
	ingressXDPBpfs  map[string]*list.List
	ingressTCBpfs   map[string]*list.List
	egressTCBpfs    map[string]*list.List
	ifaceName       string
	seqID           int
)

type mockKeyChangeEmitter struct {
	pairs   [][2]string
	handler emitter.EventHandler
}

func newMockEventEmitter(pairs [][2]string) *mockKeyChangeEmitter {
	return &mockKeyChangeEmitter{pairs: pairs}
}

func (m *mockKeyChangeEmitter) RegisterHandler(handler emitter.EventHandler) error {
	m.handler = handler
	for _, pair := range m.pairs {
		if err := m.handler.HandleAdded([]byte(pair[0]), []byte(pair[1])); err != nil {
			m.handler.HandleError(err, kvstores.Added, []byte(pair[0]), []byte(pair[1]))
		}
	}
	return nil
}

func (m *mockKeyChangeEmitter) Close() error {
	return nil
}

func setupDBTest() {
	machineHostname, _ = os.Hostname()
	var pairs [][2]string
	emit = newMockEventEmitter(pairs)
	pMon = NewpCheck(3, true, 10)
	mMon = NewpKFMetrics(true, 30)

	ingressXDPBpfs = make(map[string]*list.List)
	ingressTCBpfs = make(map[string]*list.List)
	egressTCBpfs = make(map[string]*list.List)

	return
}
func setupValidBPF() {
	bpf := BPF{
		Program: models.BPFProgram{
			ID:            1,
			Name:          "foo",
			Artifact:      "foo.tar.gz",
			CmdStart:      "foo",
			CmdStop:       "",
			Version:       "1.0",
			IsUserProgram: true,
			AdminStatus:   "DISABLED",
		},
		Cmd:          nil,
		FilePath:     "",
		RestartCount: 0,
	}
	ifaceName = "dummy"
	seqID = 1
	log.Info().Msg(bpf.Program.Name)

	return
}

func setupValData() {
	cfg := make(map[string][]*models.BPFProgram)
	ifaceName = "dummy"
	seqID = 1

	bpfProg := models.BPFProgram{
		ID:            1,
		Name:          "foo",
		Artifact:      "foo.tar.gz",
		CmdStart:      "foo",
		CmdStop:       "",
		Version:       "1.0",
		IsUserProgram: true,
		AdminStatus:   "ENABLED",
	}
	cfg[ifaceName] = make([]*models.BPFProgram, 5)
	cfg[ifaceName][seqID] = &bpfProg
	val, _ = json.Marshal(cfg)
}

func setupValVersionChange() {

	cfg := make(map[string]map[int]*models.BPFProgram)
	ifaceName = "dummy"
	seqID = 1

	bpfProg := models.BPFProgram{
		ID:            1,
		Name:          "foo",
		Artifact:      "foo.tar.gz",
		CmdStart:      "foo",
		CmdStop:       "",
		Version:       "2.0",
		IsUserProgram: true,
		AdminStatus:   "ENABLED",
	}
	cfg[ifaceName] = make(map[int]*models.BPFProgram)
	cfg[ifaceName][seqID] = &bpfProg
	valVerChange, _ = json.Marshal(cfg)
}

func setupValStatusChange() {

	cfg := make(map[string][]*models.BPFProgram)
	ifaceName = "dummy"
	seqID = 1

	bpfProg := models.BPFProgram{
		ID:            1,
		Name:          "foo",
		Artifact:      "foo.tar.gz",
		CmdStart:      "foo",
		CmdStop:       "",
		Version:       "2.0",
		IsUserProgram: true,
		AdminStatus:   "DISABLED",
	}
	cfg[ifaceName] = make([]*models.BPFProgram, 5)

	cfg[ifaceName][seqID] = &bpfProg
	valStatusChange, _ = json.Marshal(cfg)
}

func TestNewNFConfigs(t *testing.T) {
	type args struct {
		emit     *mockKeyChangeEmitter //emitter.KeyChangeEmitter
		host     string
		hostConf *config.Config
		pMon     *pCheck
		mMon     *kfMetrics
		ctx      context.Context
	}
	setupDBTest()
	tests := []struct {
		name    string
		args    args
		want    *NFConfigs
		wantErr bool
	}{
		{name: "EmptyConfig",
			args: args{emit: emit,
				host:     machineHostname,
				hostConf: nil,
				pMon:     pMon,
				mMon:     mMon},
			want: &NFConfigs{hostName: machineHostname,
				IngressXDPBpfs: ingressXDPBpfs,
				IngressTCBpfs:  ingressTCBpfs,
				EgressTCBpfs:   egressTCBpfs,
				hostConfig:     nil,
				processMon:     pMon,
				kfMetricsMon:   mMon,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewNFConfigs(tt.args.ctx, tt.args.emit, tt.args.host, tt.args.hostConf, tt.args.pMon, tt.args.mMon)
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

func TestNFConfigs_HandleAdded(t *testing.T) {
	type fields struct {
		hostName       string
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		processMon     *pCheck
		metricsMon     *kfMetrics
	}
	type args struct {
		key []byte
		val []byte
	}
	setupDBTest()
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
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: nil,
				val: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				hostName:       tt.fields.hostName,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				hostConfig:     tt.fields.hostConfig,
				processMon:     tt.fields.processMon,
				kfMetricsMon:   tt.fields.metricsMon,
			}
			if err := cfg.HandleAdded(tt.args.key, tt.args.val); (err != nil) != tt.wantErr {
				t.Errorf("NFConfigs.HandleAdded() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNFConfigs_HandleUpdated(t *testing.T) {
	type fields struct {
		hostName       string
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		processMon     *pCheck
		metricsMon     *kfMetrics
	}
	type args struct {
		key []byte
		val []byte
	}

	setupDBTest()
	setupValidBPF()
	setupValData()
	setupValVersionChange()
	setupValStatusChange()

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
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: nil,
				val: nil,
			},
			wantErr: false,
		},
		{
			name: "InvalidKey",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: []byte("dummy"),
				val: val,
			},
			wantErr: false,
		},
		{
			name: "ValidKeyInvalidVal",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     nil,
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: []byte("machineHostname"),
				val: nil,
			},
			wantErr: false,
		},
		{
			name: "ValidKeyNVal",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),

				hostConfig: &config.Config{BPFDir: "/tmp", ProximityUrl: "http://www.example.com"},
				processMon: pMon,
				metricsMon: mMon,
			},
			args: args{
				key: []byte("bpf_programs"),
				val: val,
			},
			wantErr: false,
		},
		{
			name: "PrePopulatedBPF",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", ProximityUrl: "http://www.example.com"},
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: []byte("dummy"),
				val: val,
			},
			wantErr: false,
		},
		{
			name: "NewBPFWithVersionChange",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", ProximityUrl: "http://www.example.com"},
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: []byte("dummy"),
				val: valVerChange,
			},
			wantErr: false,
		},
		{
			name: "NewBPFWithStatusChange",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: make(map[string]*list.List),
				ingressTCBpfs:  make(map[string]*list.List),
				egressTCBpfs:   make(map[string]*list.List),
				hostConfig:     &config.Config{BPFDir: "/tmp", ProximityUrl: "http://www.example.com"},
				processMon:     pMon,
				metricsMon:     mMon,
			},
			args: args{
				key: []byte("nf"),
				val: valStatusChange,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				hostName: tt.fields.hostName,
				//				configs:    tt.fields.configs,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				hostConfig:     tt.fields.hostConfig,
				processMon:     tt.fields.processMon,
			}
			if err := cfg.HandleUpdated(tt.args.key, tt.args.val); (err != nil) != tt.wantErr {
				t.Errorf("NFConfigs.HandleUpdated() error = %#v, wantErr %#v", err, tt.wantErr)
			}
		})
	}
}

func TestNFConfigs_Get(t *testing.T) {
	type fields struct {
		hostName       string
		ingressXDPBpfs map[string]*list.List
		ingressTCBpfs  map[string]*list.List
		egressTCBpfs   map[string]*list.List
		hostConfig     *config.Config
		processMon     *pCheck
	}
	type args struct {
		key string
	}

	setupDBTest()
	setupValidBPF()

	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*models.L3afDNFConfigDetail
		want1  bool
	}{
		{
			name: "InValidKey",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: ingressXDPBpfs,
				ingressTCBpfs:  ingressTCBpfs,
				egressTCBpfs:   egressTCBpfs,
				hostConfig:     nil,
				processMon:     pMon,
			},
			args: args{
				key: "dummy123",
			},
			want:  nil,
			want1: false,
		},
		{
			name: "ValidKeyEmptyVal",
			fields: fields{
				hostName:       machineHostname,
				ingressXDPBpfs: ingressXDPBpfs,
				ingressTCBpfs:  ingressTCBpfs,
				egressTCBpfs:   egressTCBpfs,
				hostConfig:     nil,
				processMon:     pMon,
			},
			args: args{
				key: "nf",
			},
			want:  nil,
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				hostName:       tt.fields.hostName,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				hostConfig:     tt.fields.hostConfig,
				processMon:     tt.fields.processMon,
			}
			got, got1 := cfg.Get(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NFConfigs.Get() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("NFConfigs.Get() got1 = %v, want %v", got1, tt.want1)
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
		processMon     *pCheck
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
				ingressXDPBpfs: ingressXDPBpfs,
				ingressTCBpfs:  ingressTCBpfs,
				egressTCBpfs:   egressTCBpfs,
				hostConfig:     nil,
				processMon:     pMon,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NFConfigs{
				hostName:       tt.fields.hostName,
				IngressXDPBpfs: tt.fields.ingressXDPBpfs,
				IngressTCBpfs:  tt.fields.ingressTCBpfs,
				EgressTCBpfs:   tt.fields.egressTCBpfs,
				hostConfig:     tt.fields.hostConfig,
				processMon:     tt.fields.processMon,
			}
			ctx, cancelfunc := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancelfunc()
			if err := cfg.Close(ctx); (err != nil) != tt.wantErr {
				t.Errorf("NFConfigs.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
