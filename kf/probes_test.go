// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"testing"
)

func TestGetProgramSectionDetails(t *testing.T) {

	tests := []struct {
		desc        string
		sectionName string
		want1       string
		want2       string
	}{
		{
			desc:        "empty section name",
			sectionName: "",
			want1:       "",
			want2:       "",
		},
		{
			desc:        "section name contains group",
			sectionName: "perf_event",
			want1:       "",
			want2:       "perf_event",
		},
		{
			desc:        "section name contains all details",
			sectionName: "tracepoint/sock/inet_sock_set_state",
			want1:       "sock",
			want2:       "inet_sock_set_state",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			got1, got2 := GetProgramSectionDetails(test.sectionName)
			if test.want1 != got1 && test.want2 != got2 {
				t.Errorf("want1 %v => got1 %v, want2 %v => got2 %v", test.want1, got1, test.want2, got2)
			}
		})
	}
}
