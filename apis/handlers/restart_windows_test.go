package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_HandleRestart(t *testing.T) {
	var req *http.Request
	req, _ = http.NewRequest("PUT", "/l3af/configs/v1/restart", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := HandleRestart(nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Error("Handle restart Failed")
	}
}
