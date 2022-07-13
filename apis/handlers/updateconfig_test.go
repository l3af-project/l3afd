package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/kf"
)

func Test_UpdateConfig(t *testing.T) {

	tests := []struct {
		name   string
		Body   *strings.Reader
		header map[string]string
		status int
		cfg    *kf.NFConfigs
	}{
		{
			name:   "NilBody",
			Body:   nil,
			status: http.StatusOK,
			cfg: &kf.NFConfigs{
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
		},
		{
			name:   "FailedToUnmarshal",
			Body:   strings.NewReader("Something"),
			status: http.StatusInternalServerError,
			header: map[string]string{},
			cfg: &kf.NFConfigs{
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
		},
		{
			name:   "UnknownHostName",
			Body:   strings.NewReader(dummypayload),
			status: http.StatusInternalServerError,
			header: map[string]string{},
			cfg: &kf.NFConfigs{
				HostName: "dummy",
				HostConfig: &config.Config{
					L3afConfigStoreFileName: filepath.FromSlash("../../testdata/Test_l3af-config.json"),
				},
			},
		},
	}
	for _, tt := range tests {
		var req *http.Request
		if tt.Body == nil {
			req, _ = http.NewRequest("POST", "/l3af/configs/v1/update", nil)
		} else {
			req, _ = http.NewRequest("POST", "/l3af/configs/v1/update", tt.Body)
		}
		for key, val := range tt.header {
			req.Header.Set(key, val)
		}
		rr := httptest.NewRecorder()
		handler := UpdateConfig(context.Background(), tt.cfg)
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.status {
			t.Error("UpdateConfig Failed")
		}
	}
}
