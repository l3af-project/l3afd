// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package apis

import (
	"reflect"
	"testing"
)

func TestMatchHostnamesWithRegexp(t *testing.T) {
	type args struct {
		pattern string
		host    string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "EmptypCheck",
			args:    args{pattern: "", host: ""},
			want:    false,
			wantErr: false,
		},
		{
			name:    "LengthMissMatchCheck",
			args:    args{pattern: "l3afd-lfn.us.l3af.io", host: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "LengthMatchCheck",
			args:    args{pattern: "l3afd-lfn.l3af.io", host: "l3afd-lfn.l3af.io"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "LengthMatchPatternMissCheck",
			args:    args{pattern: "l3afd-us.l3af.io", host: "l3afd-lf.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternMatchCheck",
			args:    args{pattern: "l3afd-*.l3af.io", host: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternMissMatchCheck",
			args:    args{pattern: "*l3afd-.l3af.io", host: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: true,
		},
		{
			name:    "PatternRegExMatchCheck",
			args:    args{pattern: "asnl3afd-lfn.l3af.io", host: ".*l3afd-lfn.l3af.io"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExExactMatchCheck",
			args:    args{pattern: "l3afd-dev.l3af.io", host: "^dev.l3af.io$"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternRegExFindMatch",
			args:    args{pattern: "l3afd-dev.l3af.io", host: "dev.l3af.io"},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchHostnamesWithRegexp(tt.args.pattern, tt.args.host)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchHostnamesWithRegexp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchExactly(t *testing.T) {
	type args struct {
		hostA string
		hostB string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "EmptypCheck",
			args:    args{hostA: "", hostB: ""},
			want:    false,
			wantErr: false,
		},
		{
			name:    "ExactMatchCheck",
			args:    args{hostA: "l3afd-lfn.l3af.io", hostB: "l3afd-lfn.l3af.io"},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchExactly(tt.args.hostA, tt.args.hostB)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}
