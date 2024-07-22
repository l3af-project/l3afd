// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

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
		file, err := json.MarshalIndent(bpfProgs, "", " ")
		if err != nil {
			log.Error().Err(err).Msgf("failed to marshal configs to save")
			statusCode = http.StatusInternalServerError
			return
		}
		if err = os.WriteFile("/var/l3afd/l3af_meta.json", file, 0644); err != nil {
			log.Error().Err(err).Msgf("failed write to file operation")
			statusCode = http.StatusInternalServerError
		}
		var files []*os.File
		cnt := 1
		for _, a := range bpfcfg.IngressXDPBpfs {
			for e := a.Front(); e != nil; e = e.Next() {
				b := e.Value.(*bpfprogs.BPF)
				if b.XDPLink != nil {
					fd := b.XDPLink.(models.FDer)
					newFile := os.NewFile(uintptr(fd.FD()), "dupFd"+strconv.Itoa(cnt))
					cnt += 1
					files = append(files, newFile)
				}
			}
		}
		// we have added
		for _, l := range models.AllNetListeners {
			lf, err := l.File()
			if err != nil {
				log.Error().Msgf("%v", err)
				statusCode = http.StatusInternalServerError
				return
			}
			newFile := os.NewFile(uintptr(lf.Fd()), "dupFd"+strconv.Itoa(cnt))
			cnt = cnt + 1
			files = append(files, newFile)
		}

		cmd := exec.Command("/root/test/l3afd", "--config", "/root/test/l3afd_reload.cfg")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = files

		log.Info().Msg("Starting chiled Process")
		err = cmd.Start()
		if err != nil {
			log.Error().Msgf("%v", err)
			statusCode = http.StatusInternalServerError
			return
		}

		log.Info().Msg("Started chiled Process")
		// if err := os.Remove("/var/l3afd/l3af_meta.json"); err != nil {
		// 	if !os.IsNotExist(err) {
		// 		log.Warn().Msgf("Meta json file: %s program type %s map file remove unsuccessfully - %s err - %#v", "/var/l3afd/l3af_meta.json", err)
		// 	}
		// }
		time.Sleep(time.Second * 10)
		os.Exit(0)
	}
}
