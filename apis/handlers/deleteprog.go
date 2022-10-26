// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/models"
)

// DeleteEbpfPrograms   remove eBPF programs on node
// @Summary Removes eBPF Programs on node
// @Description Removes eBPF Programs on node
// @Accept  json
// @Produce  json
// @Param cfgs body []models.L3afBPFProgramNames true "BPF program names"
// @Success 200
// @Router /l3af/configs/v1/delete [post]
func DeleteEbpfPrograms(ctx context.Context, kfcfg *kf.NFConfigs) http.HandlerFunc {

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

		if r.Body == nil {
			log.Warn().Msgf("Empty request body")
			return
		}
		bodyBuffer, err := io.ReadAll(r.Body)
		if err != nil {
			mesg = fmt.Sprintf("failed to read request body: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			return
		}

		var t []models.L3afBPFProgramNames
		if err := json.Unmarshal(bodyBuffer, &t); err != nil {
			mesg = fmt.Sprintf("failed to unmarshal payload: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			return
		}

		if err := kfcfg.DeleteEbpfPrograms(t); err != nil {
			mesg = fmt.Sprintf("failed to DeleteEbpfPrograms : %v", err)
			log.Error().Msg(mesg)

			statusCode = http.StatusInternalServerError
			return
		}
	}
}
