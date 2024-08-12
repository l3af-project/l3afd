// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
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
	"github.com/l3af-project/l3afd/v2/pidfile"
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
		if models.IsReadOnly {
			log.Warn().Msgf("We are in Between Restart Please try after some time")
			mesg = "We are in Between Restart Please try after some time"
			statusCode = http.StatusInternalServerError
			return
		}
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
		ln, err := net.Listen("unix", bpfcfg.HostConfig.HostSock)
		if err != nil {
			log.Err(err)
			statusCode = http.StatusInternalServerError
			return
		}
		srverror := make(chan error, 1)
		go func() {
			defer ln.Close()
			conn, err := ln.Accept()
			if err != nil {
				log.Err(err)
				srverror <- err
				return
			}
			defer conn.Close()
			encoder := gob.NewEncoder(conn)
			err = encoder.Encode(bpfProgs)
			if err != nil {
				log.Err(err)
				srverror <- err
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
		cmd := exec.Command("/root/test/l3afd", "--config", "/Users/a0p0ie5/lima-dev/l3afd/l3afd.cfg")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = files
		// checking srv error
		if len(srverror) == 1 {
			statusCode = http.StatusInternalServerError
			log.Err(<-srverror)
			return
		}
		bpfcfg.StopAllProbes()
		log.Info().Msg("Starting child Process")
		err = cmd.Start()
		if err != nil {
			log.Error().Msgf("%v", err)
			statusCode = http.StatusInternalServerError
			err = cmd.Process.Kill()
			if err != nil {
				fmt.Println(err)
			}
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
			}
			err = pidfile.CreatePID(bpfcfg.HostConfig.PIDFilename)
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
			for i := 1; i <= 7; i++ {
				conn, err = net.Dial("unix", bpfcfg.HostConfig.StateSock)
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
		for i := 0; i < 7; i++ {
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
			err = cmd.Process.Kill()
			if err != nil {
				fmt.Println(err)
			}
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
			}
			err = pidfile.CreatePID(bpfcfg.HostConfig.PIDFilename)
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
