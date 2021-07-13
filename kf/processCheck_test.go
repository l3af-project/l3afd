// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"container/list"
	"reflect"
	"testing"
	"time"
)

func TestNewpCheck(t *testing.T) {
	type args struct {
		rc       int
		chain    bool
		interval time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    *pCheck
		wantErr bool
	}{
		{
			name:    "EmptypCheck",
			args:    args{rc: 0, chain: false, interval: 0},
			want:    &pCheck{MaxRetryCount: 0},
			wantErr: false,
		},
		{
			name:    "ValidpCheck",
			args:    args{rc: 3, chain: true, interval: 10},
			want:    &pCheck{MaxRetryCount: 3},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewpCheck(tt.args.rc, false, 0)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewpCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pCheck_pCheckStart(t *testing.T) {
	type fields struct {
		MaxRetryCount     int
		chain             bool
		retryMonitorDelay time.Duration
	}
	type args struct {
		IngressXDPbpfProgs map[string]*list.List
		IngressTCbpfProgs  map[string]*list.List
		EgressTCbpfProgs   map[string]*list.List
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "EmptyBPF",
			fields: fields{MaxRetryCount: 3, chain: true, retryMonitorDelay: 10},
			args: args{IngressXDPbpfProgs: make(map[string]*list.List),
				IngressTCbpfProgs: make(map[string]*list.List),
				EgressTCbpfProgs:  make(map[string]*list.List),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pCheck{
				MaxRetryCount:     tt.fields.MaxRetryCount,
				Chain:             tt.fields.chain,
				retryMonitorDelay: tt.fields.retryMonitorDelay,
			}
			c.pCheckStart(tt.args.IngressXDPbpfProgs, tt.args.IngressTCbpfProgs, tt.args.EgressTCbpfProgs)
		})
	}
}
