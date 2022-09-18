// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package apis

import (
	"reflect"
	"testing"
)

func TestMatchHostnamesWithRegexp(t *testing.T) {
	type args struct {
		dnsName      string
		sanMatchRule string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "EmptyCheck",
			args:    args{dnsName: "", sanMatchRule: ""},
			want:    false,
			wantErr: false,
		},
		{
			name:    "LengthMissMatchCheck",
			args:    args{dnsName: "l3afd-lfn.us.l3af.io", sanMatchRule: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "LengthMatchCheck",
			args:    args{dnsName: "l3afd-lfn.l3af.io", sanMatchRule: "l3afd-lfn.l3af.io"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "LengthMatchPatternMissCheck",
			args:    args{dnsName: "l3afd-us.l3af.io", sanMatchRule: "l3afd-lf.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternMatchCheck",
			args:    args{dnsName: "l3afd-*.l3af.io", sanMatchRule: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternMissMatchCheck",
			args:    args{dnsName: "*l3afd-.l3af.io", sanMatchRule: "l3afd-lfn.l3af.io"},
			want:    false,
			wantErr: true,
		},
		{
			name:    "PatternRegExMatchCheck",
			args:    args{dnsName: "asnl3afd-lfn.l3af.io", sanMatchRule: ".*l3afd-lfn.l3af.io"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExExactMatchCheck",
			args:    args{dnsName: "l3afd-dev.l3af.io", sanMatchRule: "^dev.l3af.io$"},
			want:    false,
			wantErr: false,
		},
		{
			name:    "PatternRegExFindMatch",
			args:    args{dnsName: "l3afd-dev.l3af.io", sanMatchRule: "dev.l3af.io"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExFindMatchPattern",
			args:    args{dnsName: "l3afd-dev-10.l3af.io", sanMatchRule: "^l3afd-dev-[0-9][0-9]\\.l3af\\.io$"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExLowerCaseMatch",
			args:    args{dnsName: "l3afd-dev-a0.l3af.io", sanMatchRule: "^l3afd-dev-[a-z][0-9]\\.l3af\\.io$"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExUpperCaseMatch",
			args:    args{dnsName: "l3afd-dev-A0.l3af.io", sanMatchRule: "^l3afd-dev-[A-Z][0-9]\\.l3af\\.io$"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "PatternRegExPanicCheck",
			args:    args{dnsName: "l3afd-dev-A0.l3af.io", sanMatchRule: "*l3afd-dev.l3af.io"},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchHostnamesWithRegexp(tt.args.dnsName, tt.args.sanMatchRule)
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
			name:    "EmptyCheck",
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

func TestToLowerCaseASCII(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "EmptyCheck",
			args:    args{in: ""},
			want:    "",
			wantErr: false,
		},
		{
			name:    "RegexLowerCheck",
			args:    args{in: "^l3afd-dev-[0-9][0-9]\\.l3af\\.io$"},
			want:    "^l3afd-dev-[0-9][0-9]\\.l3af\\.io$",
			wantErr: false,
		},
		{
			name:    "RegexUpperValueCheck",
			args:    args{in: "^L3AFd-dev-[0-9][0-9]\\.l3af\\.io$"},
			want:    "^l3afd-dev-[0-9][0-9]\\.l3af\\.io$",
			wantErr: false,
		},
		{
			name:    "RegexLowerCheckRuneError",
			args:    args{in: "^�l3afd-dev-[0-9][0-9]\\.l3af\\.io$"},
			want:    "^�l3afd-dev-[0-9][0-9]\\.l3af\\.io$",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toLowerCaseASCII(tt.args.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matchHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}
