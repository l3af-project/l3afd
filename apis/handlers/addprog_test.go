package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/config"
	"github.com/l3af-project/l3afd/v2/models"
)

const dummypayload string = `[
	{
	  "host_name" : "l3af-local-test",
	  "iface" : "fakeif0",
	  "bpf_programs" : {
		"xdp_ingress" : [
		],
		"tc_egress": [
		],
		"tc_ingress": [
		]
	  }
	}
  ]
  `

func Test_addprog(t *testing.T) {

	tests := []struct {
		name       string
		Body       *strings.Reader
		header     map[string]string
		status     int
		cfg        *bpfprogs.NFConfigs
		isreadonly bool
	}{
		{
			name:       "NilBody",
			Body:       nil,
			status:     http.StatusOK,
			isreadonly: false,
			cfg: &bpfprogs.NFConfigs{
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
		},
		{
			name:       "FailedToUnmarshal",
			Body:       strings.NewReader("Something"),
			status:     http.StatusInternalServerError,
			header:     map[string]string{},
			isreadonly: false,
			cfg: &bpfprogs.NFConfigs{
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
		},
		{
			name: "EmptyInput",
			Body: strings.NewReader("[]"),
			header: map[string]string{
				"Content-Type": "application/json",
			},
			isreadonly: false,
			cfg: &bpfprogs.NFConfigs{
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
			status: http.StatusOK,
		},
		{
			name:   "UnknownHostName",
			Body:   strings.NewReader(dummypayload),
			status: http.StatusInternalServerError,
			header: map[string]string{},
			cfg: &bpfprogs.NFConfigs{
				HostName: "dummy",
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
			isreadonly: false,
		},
		{
			name: "InReadonly",
			Body: nil,
			header: map[string]string{
				"Content-Type": "application/json",
			},
			isreadonly: true,
			cfg:        nil,
			status:     http.StatusOK,
		},
	}
	for _, tt := range tests {
		var req *http.Request
		if tt.Body == nil {
			req, _ = http.NewRequest("POST", "/l3af/configs/v1/add", nil)
		} else {
			req, _ = http.NewRequest("POST", "/l3af/configs/v1/add", tt.Body)
		}
		for key, val := range tt.header {
			req.Header.Set(key, val)
		}
		models.IsReadOnly = tt.isreadonly
		rr := httptest.NewRecorder()
		handler := AddEbpfPrograms(context.Background(), tt.cfg)
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.status {
			models.IsReadOnly = false
			t.Error("AddEbpfPrograms Failed")
		}
		models.IsReadOnly = false
	}
}
