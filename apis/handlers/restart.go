// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"os"

	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/models"
)

// DeleteEbpfPrograms   remove eBPF programs on node
// @Summary Removes eBPF Programs on node
// @Description Removes eBPF Programs on node
// @Accept  json
// @Produce  json
// @Param cfgs body []models.L3afBPFProgramNames true "BPF program names"
// @Success 200
// @Router /l3af/configs/v1/restart [post]
func HandleRestart(ctx context.Context, bpfcfg *bpfprogs.NFConfigs) http.HandlerFunc {
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
		bpfProgs := bpfcfg.GetL3AFHOSTDATA()
		bpfProgs.InRestart = true
		file, err := json.MarshalIndent(bpfProgs, "", " ")
		if err != nil {
			log.Error().Err(err).Msgf("failed to marshal configs to save")
			statusCode = http.StatusInternalServerError
			return
		}
		if err = os.WriteFile(bpfcfg.HostConfig.RestartDataFile, file, 0644); err != nil {
			log.Error().Err(err).Msgf("failed write to file operation")
			statusCode = http.StatusInternalServerError
		}
		models.CloseForRestart <- struct{}{}
	}
}
