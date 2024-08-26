package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3af-project/l3afd/v2/models"
)

func Test_HandleRestart(t *testing.T) {
	var req *http.Request
	req, _ = http.NewRequest("PUT", "/l3af/configs/v1/restart", nil)
	req.Header.Set("Content-Type", "application/json")
	models.IsReadOnly = true
	rr := httptest.NewRecorder()
	handler := HandleRestart(nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		models.IsReadOnly = false
		t.Error("Handle restart Failed")
	}
	models.IsReadOnly = false
}
