// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/gob"
	"fmt"
	"net"
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

// HandleRestart Store meta data about ebpf programs and exit
// @Summary Store meta data about ebpf programs and exit
// @Description Store meta data about ebpf programs and exit
// @Accept  json
// @Produce  json
// @Param cfgs body []models.L3afBPFPrograms true "BPF programs"
// @Success 200
// @Router /l3af/configs/v1/restart [put]
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
		defer func() {
			models.IsReadOnly = false
		}()
		models.IsReadOnly = true
		// complete current requests
		for {
			models.StateLock.Lock()
			if models.CurrentWriteReq == 0 {
				models.StateLock.Unlock()
				break
			}
			models.StateLock.Unlock()
		}
		// Now our system is in Readonly state
		bpfProgs := bpfcfg.GetL3AFHOSTDATA()
		bpfProgs.InRestart = true
		ln, err := net.Listen("unix", "/tmp/l3afd.sock")
		if err != nil {
			statusCode = http.StatusInternalServerError
			return
		}
		srverror := make(chan error, 1)
		go func() {
			defer ln.Close()
			conn, err := ln.Accept()
			if err != nil {
				srverror <- err
				log.Err(err)
				return
			}
			defer conn.Close()
			encoder := gob.NewEncoder(conn)
			err = encoder.Encode(bpfProgs)
			if err != nil {
				srverror <- err
				log.Err(err)
				return
			}
		}()
		files := make([]*os.File, 3)
		srvToIndex := make(map[string]int)
		srvToIndex["stat_http"] = 0
		srvToIndex["main_http"] = 1
		srvToIndex["debug_http"] = 2
		for srv, lis := range models.AllNetListeners {
			idx := srvToIndex[srv]
			lf, err := lis.File()
			if err != nil {
				log.Error().Msgf("%v", err)
				statusCode = http.StatusInternalServerError
				return
			}
			newFile := os.NewFile(uintptr(lf.Fd()), "dupFdlistner"+strconv.Itoa(idx))
			files[idx] = newFile
		}
		// we have added
		cmd := exec.Command("/root/test/l3afd", "--config", "/root/test/l3afd_reload.cfg")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = files
		log.Info().Msg("Starting chiled Process")
		// checking srv error
		if len(srverror) == 1 {
			statusCode = http.StatusInternalServerError
			log.Err(<-srverror)
			return
		}
		bpfcfg.StopAllProbes()
		err = cmd.Start()
		if err != nil {
			log.Error().Msgf("%v", err)
			statusCode = http.StatusInternalServerError
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
			}
			return
		}
		NewProcessStatus := make(chan string)
		go func() {
			// I need to write client code for reading the state of new process
			var err error
			var conn net.Conn
			f := false
			for i := 1; i <= 10; i++ {
				conn, err = net.Dial("unix", "/tmp/l3afstate.sock")
				if err == nil {
					f = true
					break
				}
				fmt.Println("Waiting for socket to be up...")
				time.Sleep(time.Second) // sleep for a second before trying again
			}
			if !f {
				NewProcessStatus <- "Failed"
				return
			}
			defer conn.Close()
			decoder := gob.NewDecoder(conn)
			var data string
			err = decoder.Decode(&data)
			if err != nil {
				NewProcessStatus <- "Failed"
				return
			}
			NewProcessStatus <- data
		}()
		// time to bootup
		for i := 0; i < 10; i++ {
			if len(srverror) == 1 {
				statusCode = http.StatusInternalServerError
				log.Err(<-srverror)
				return
			}
			time.Sleep(1 * time.Second)
		}
		st := <-NewProcessStatus
		if st == "Failed" {
			// write a function a to do cleanup of other process if necessary
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
			}
			statusCode = http.StatusInternalServerError
			return
		} else {
			models.CloseForRestart <- struct{}{}
		}
	}
}
