// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"container/list"
	"reflect"
	"testing"
)

func TestNewpKFMetrics(t *testing.T) {
	type args struct {
		chain    bool
		interval int
	}
	tests := []struct {
		name    string
		args    args
		want    *kfMetrics
		wantErr bool
	}{
		{
			name:    "EmptypCheck",
			args:    args{chain: false, interval: 0},
			want:    &kfMetrics{Chain: false, Intervals: 0},
			wantErr: false,
		},
		{
			name:    "ValidpCheck",
			args:    args{chain: true, interval: 10},
			want:    &kfMetrics{Chain: true, Intervals: 10},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewpKFMetrics(tt.args.chain, tt.args.interval)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKFMetrics() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_KFMetrics_Start(t *testing.T) {
	type fields struct {
		Chain    bool
		Interval int
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
			fields: fields{Chain: true, Interval: 10},
			args: args{IngressXDPbpfProgs: make(map[string]*list.List),
				IngressTCbpfProgs: make(map[string]*list.List),
				EgressTCbpfProgs:  make(map[string]*list.List),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &kfMetrics{
				Chain:     tt.fields.Chain,
				Intervals: tt.fields.Interval,
			}
			c.kfMetricsStart(tt.args.IngressXDPbpfProgs, tt.args.IngressTCbpfProgs, tt.args.EgressTCbpfProgs)
		})
	}
}
