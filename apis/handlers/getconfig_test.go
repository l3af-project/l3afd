package handlers

import (
	"container/list"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	chi "github.com/go-chi/chi/v5"
	"github.com/l3af-project/l3afd/kf"
)

func Test_GetConfig(t *testing.T) {
	tests := []struct {
		name   string
		iface  string
		status int
		cfg    *kf.NFConfigs
	}{
		{
			name:   "EmptyInterfaceInRequest",
			iface:  "",
			status: http.StatusBadRequest,
			cfg:    &kf.NFConfigs{},
		},
		{
			name:   "GoodInput",
			iface:  "fakeif0",
			status: http.StatusOK,
			cfg: &kf.NFConfigs{
				IngressXDPBpfs: map[string]*list.List{"fakeif0": nil},
				IngressTCBpfs:  map[string]*list.List{"fakeif0": nil},
				EgressTCBpfs:   map[string]*list.List{"fakeif0": nil},
			},
		},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "l3af/configs/v1/"+tt.iface, nil)
		rctx := chi.NewRouteContext()
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rctx.URLParams.Add("iface", tt.iface)
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(GetConfig)
		InitConfigs(tt.cfg)
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.status {
			t.Errorf("GetConfig Failed")
		}
	}
}

func Test_GetConfigAll(t *testing.T) {
	tests := []struct {
		name   string
		status int
		cfg    *kf.NFConfigs
	}{
		{
			name:   "GoodInput",
			status: http.StatusOK,
			cfg:    &kf.NFConfigs{},
		},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "l3af/configs/v1", nil)
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(GetConfigAll)
		InitConfigs(tt.cfg)
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.status {
			t.Errorf("GetConfigAll Failed")
		}
	}
}
