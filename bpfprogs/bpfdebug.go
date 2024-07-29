// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

var bpfcfgs *NFConfigs

func SetupBPFDebug(ebpfChainDebugAddr string, BPFConfigs *NFConfigs) {
	bpfcfgs = BPFConfigs
	go func() {
		http.HandleFunc("/bpfs/", ViewHandler)
		// We just need to start a server.
		log.Info().Msg("Starting BPF debug server")
		if err := http.ListenAndServe(ebpfChainDebugAddr, nil); err != nil {
			log.Fatal().Err(err).Msg("failed to start BPF chain debug server")
		}
	}()
}

func ViewHandler(w http.ResponseWriter, r *http.Request) {

	iface := strings.TrimPrefix(r.URL.Path, "/bpfs/")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(bpfcfgs.BPFDetails(iface)); err != nil {
		log.Err(err).Msgf("unable to serialize json")
	}
}
