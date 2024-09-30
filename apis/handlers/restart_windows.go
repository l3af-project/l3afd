// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/l3af-project/l3afd/v2/bpfprogs"
)

// HandleRestart Store meta data about ebpf programs and exit
// @Summary Store meta data about ebpf programs and exit
// @Description Store meta data about ebpf programs and exit
// @Accept  json
// @Produce  json
// @Param cfgs body []models.L3afBPFPrograms true "BPF programs"
// @Success 200
// @Router /l3af/configs/v1/restart [put]
func HandleRestart(bpfcfg *bpfprogs.NFConfigs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mesg := ""
		statusCode := http.StatusOK
		w.Header().Add("Content-Type", "application/json")
		defer func(mesg *string, statusCode *int) {
			w.WriteHeader(*statusCode)
			_, err := w.Write([]byte(*mesg))
			if err != nil {
				log.Warn().Msgf("Failed to write response bytes: %v", err)
			}
		}(&mesg, &statusCode)
		mesg = "Graceful restart is only supported for linux as of now"
	}
}
