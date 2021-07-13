// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"encoding/json"
	"net/http"
	"strings"

	"tbd/go-shared/logs"
)

var kfcfgs *NFConfigs

func SetupKFDebug(ebpfChainDebugAddr string, kfConfigs *NFConfigs) {
	kfcfgs = kfConfigs
	go func() {
		http.HandleFunc("/kfs/", ViewHandler)

		// We just need to start a server.
		logs.IfErrorLogf(http.ListenAndServe(ebpfChainDebugAddr, nil), "failed to start KF chain debug server")
		logs.Infof("KF debug server started")
	}()
}

func ViewHandler(w http.ResponseWriter, r *http.Request) {

	iface := strings.TrimPrefix(r.URL.Path, "/kfs/")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(kfcfgs.KFDetails(iface))
}
