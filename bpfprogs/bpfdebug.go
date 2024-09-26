// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package bpfprogs

import (
	"encoding/json"
	"errors"
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
		if _, ok := models.AllNetListeners.Load("debug_http"); !ok {
			tcpAddr, err := net.ResolveTCPAddr("tcp", ebpfChainDebugAddr)
			if err != nil {
				log.Fatal().Err(err).Msgf("unable to resolve tcpaddr %v ", ebpfChainDebugAddr)
				return
			}
			listener, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				log.Fatal().Err(err).Msgf("unable to create tcp listener")
			}
			models.AllNetListeners.Store("debug_http", listener)
		}
		http.HandleFunc("/bpfs/", ViewHandler)
		// We just need to start a server.
		log.Info().Msg("Starting BPF debug server")
		val, _ := models.AllNetListeners.Load("debug_http")
		l, _ := val.(*net.TCPListener)
		if err := http.Serve(l, nil); !errors.Is(err, http.ErrServerClosed) {
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
