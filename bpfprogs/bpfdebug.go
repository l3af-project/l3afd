// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/l3af-project/l3afd/v2/models"
	"github.com/rs/zerolog/log"
)

var bpfcfgs *NFConfigs

func SetupBPFDebug(ebpfChainDebugAddr string, BPFConfigs *NFConfigs) {
	bpfcfgs = BPFConfigs
	go func() {
		if _, ok := models.AllNetListeners["debug_http"]; !ok {
			tcpAddr, err := net.ResolveTCPAddr("tcp", ebpfChainDebugAddr)
			if err != nil {
				fmt.Println("Error resolving TCP address:", err)
				return
			}
			listener, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				log.Fatal().Err(err).Msgf("Not able to create net Listen")
			}
			models.AllNetListeners["debug_http"] = listener
		}
		http.HandleFunc("/bpfs/", ViewHandler)
		// We just need to start a server.
		log.Info().Msg("Starting BPF debug server")
		if err := http.Serve(models.AllNetListeners["debug_http"], nil); err != nil {
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
