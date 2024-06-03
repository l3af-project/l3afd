// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"container/list"
	"reflect"
	"testing"
)

func TestNewpBPFMetrics(t *testing.T) {
	type args struct {
		chain    bool
		interval int
	}
	tests := []struct {
		name    string
		args    args
		want    *bpfMetrics
		wantErr bool
	}{
		{
			name:    "EmptypCheck",
			args:    args{chain: false, interval: 0},
			want:    &bpfMetrics{Chain: false, Intervals: 0},
			wantErr: false,
		},
		{
			name:    "ValidpCheck",
			args:    args{chain: true, interval: 10},
			want:    &bpfMetrics{Chain: true, Intervals: 10},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewpBPFMetrics(tt.args.chain, tt.args.interval)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewBPFMetrics() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_BPFMetrics_Start(t *testing.T) {
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
			c := &bpfMetrics{
				Chain:     tt.fields.Chain,
				Intervals: tt.fields.Interval,
			}
			c.bpfMetricsStart(tt.args.IngressXDPbpfProgs, tt.args.IngressTCbpfProgs, tt.args.EgressTCbpfProgs)
		})
	}
}
