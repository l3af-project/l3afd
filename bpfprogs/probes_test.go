// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"testing"
)

func TestGetProgramSectionDetails(t *testing.T) {

	tests := []struct {
		desc        string
		sectionName string
		want1       string
		want2       string
		want3       string
	}{
		{
			desc:        "empty section name",
			sectionName: "",
			want1:       "",
			want2:       "",
		},
		{
			desc:        "section name contains group",
			sectionName: "kprobe/perf_event",
			want1:       "kprobe",
			want2:       "perf_event",
			want3:       "",
		},
		{
			desc:        "section name contains all details",
			sectionName: "tracepoint/sock/inet_sock_set_state",
			want1:       "tracepoint",
			want2:       "sock",
			want3:       "inet_sock_set_state",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			got1, got2, got3 := GetProgramSectionDetails(test.sectionName)
			if test.want1 != got1 && test.want2 != got2 && test.want3 != got3 {
				t.Errorf("want1 %v => got1 %v, want2 %v => got2 %v, want3 %v => got3 %v", test.want1, got1, test.want2, got2, test.want3, got3)
			}
		})
	}
}
