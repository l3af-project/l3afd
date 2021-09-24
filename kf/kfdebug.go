// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

var kfcfgs *NFConfigs

func SetupKFDebug(ebpfChainDebugAddr string, kfConfigs *NFConfigs) {
	kfcfgs = kfConfigs
	go func() {
		http.HandleFunc("/kfs/", ViewHandler)

		// We just need to start a server.
		log.Info().Msg("Starting KF debug server")
		if err := http.ListenAndServe(ebpfChainDebugAddr, nil); err != nil {
			log.Fatal().Err(err).Msg("failed to start KF chain debug server")
		}
	}()
}

func ViewHandler(w http.ResponseWriter, r *http.Request) {

	iface := strings.TrimPrefix(r.URL.Path, "/kfs/")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(kfcfgs.KFDetails(iface))
}
