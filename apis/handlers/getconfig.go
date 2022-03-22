// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"github.com/l3af-project/l3afd/kf"
	"github.com/rs/zerolog/log"
	"net/http"
	"strings"
)

var kfcfgs *kf.NFConfigs

func InitConfigs(cfgs *kf.NFConfigs) error {
	kfcfgs = cfgs
	return nil
}

func GetConfig(w http.ResponseWriter, r *http.Request) {
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

	url := r.URL.Path
	iface := strings.TrimSpace(url[strings.LastIndex(url, "/")+1:])
	if iface == "" {
		mesg = "iface value is empty"
		log.Error().Msgf(mesg)
		statusCode = http.StatusBadRequest
		return
	}

	resp, err := json.MarshalIndent(kfcfgs.EBPFPrograms(iface), "", "  ")
	if err != nil {
		mesg = "internal server error"
		log.Error().Msgf("failed to marshal response: %v", err)
		statusCode = http.StatusInternalServerError
		return
	}
	mesg = string(resp)
}
