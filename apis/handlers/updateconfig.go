// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"

	"io/ioutil"
	"net/http"

	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/models"
)

func UpdateConfig(ctx context.Context, kfcfg *kf.NFConfigs) http.HandlerFunc {

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

		bodyBuffer, _ := ioutil.ReadAll(r.Body)
		var t []models.L3afBPFPrograms
		err := json.Unmarshal(bodyBuffer, &t)
		if err != nil {
			mesg = fmt.Sprintf("failed to unmarshal payload: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			return
		}

		if err := kfcfg.DeployeBPFPrograms(t); err != nil {
			mesg = fmt.Sprintf("failed to deploy ebpf programs: %v", err)
			log.Error().Msg(mesg)

			statusCode = http.StatusInternalServerError
			return
		}
	}
}
