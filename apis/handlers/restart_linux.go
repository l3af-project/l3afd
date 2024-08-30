// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/l3af-project/l3afd/v2/bpfprogs"
	"github.com/l3af-project/l3afd/v2/models"
	"github.com/l3af-project/l3afd/v2/pidfile"
	"github.com/l3af-project/l3afd/v2/restart"
)

// HandleRestart will start new instance of l3afd provided by payload
// @Summary this api will start new instance of l3afd provided by payload
// @Description this api will start new instance of l3afd provided by payload
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

		var t models.RestartConfig
		if err := json.Unmarshal(bodyBuffer, &t); err != nil {
			mesg = fmt.Sprintf("failed to unmarshal payload: %v", err)
			log.Error().Msg(mesg)
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
			time.Sleep(time.Millisecond)
		}

		err, oldCfgPath := restart.ReadSymlink(bpfcfg.HostConfig.BasePath + "/latest/l3afd.cfg")
		if err != nil {
			mesg = fmt.Sprintf("failed read simlink: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			return
		}
		err, oldBinPath := restart.ReadSymlink(bpfcfg.HostConfig.BasePath + "/latest/l3afd")
		if err != nil {
			mesg = fmt.Sprintf("failed to read simlink: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			return
		}
		oldVersion := strings.Split(strings.Trim(oldBinPath, bpfcfg.HostConfig.BasePath+"/"), "/")[0]

		err = restart.GetNewVersion(t.ArtifactURL, oldVersion, t.Version, bpfcfg.HostConfig)
		if err != nil {
			mesg = fmt.Sprintf("failed to getNewVersion: %v", err)
			log.Error().Msg(mesg)
			statusCode = http.StatusInternalServerError
			err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
			mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
			return
		}
		// Now our system is in Readonly state
		bpfProgs := bpfcfg.GetL3AFHOSTDATA()
		ln, err := net.Listen("unix", models.HostSock)
		if err != nil {
			log.Err(err)
			err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
			mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
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
			srverror <- nil
		}()
		files := make([]*os.File, 3)
		srvToIndex := make(map[string]int)
		srvToIndex["stat_http"] = 0
		srvToIndex["main_http"] = 1
		srvToIndex["debug_http"] = 2
		isErr := false
		models.AllNetListeners.Range(func(srvr, listr interface{}) bool { // iterate over the map
			srv, _ := srvr.(string)
			lis, _ := listr.(*net.TCPListener)
			idx := srvToIndex[srv]
			lf, err := lis.File()
			if err != nil {
				log.Error().Msgf("%v", err)
				err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
				mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
				statusCode = http.StatusInternalServerError
				isErr = true
				return false
			}
			newFile := os.NewFile(uintptr(lf.Fd()), "dupFdlistner"+strconv.Itoa(idx))
			files[idx] = newFile
			return true
		})
		if isErr {
			return
		}
		// we have added
		cmd := exec.Command(bpfcfg.HostConfig.BasePath+"/latest/l3afd", "--config", bpfcfg.HostConfig.BasePath+"/latest/l3afd.cfg")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.ExtraFiles = files
		bpfcfg.StopAllProbes()
		log.Info().Msg("Starting child Process")
		err = cmd.Start()
		if err != nil {
			log.Error().Msgf("%v", err)
			mesg = mesg + fmt.Sprintf("not able to start new instance %v", err)
			// write a function a to do cleanup of other process if necessary
			err = cmd.Process.Kill()
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to kill the new instance %v", err)
			}
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to start all userprograms and probes: %v", err)
			}
			err = pidfile.CreatePID(bpfcfg.HostConfig.PIDFilename)
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to create pid file: %v", err)
			}
			err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
			if err != nil {
				mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
			}
			statusCode = http.StatusInternalServerError
			return
		}
		NewProcessStatus := make(chan string)
		go func() {
			// I need to write client code for reading the state of new process
			var err error
			var conn net.Conn
			f := false
			for i := 1; i <= bpfcfg.HostConfig.TimetoRestart; i++ {
				conn, err = net.Dial("unix", models.StateSock)
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
		select {
		case terr := <-srverror:
			if terr != nil {
				statusCode = http.StatusInternalServerError
				// write a function a to do cleanup of other process if necessary
				err = cmd.Process.Kill()
				if err != nil {
					log.Error().Msgf("%v", err)
					mesg = mesg + fmt.Sprintf("not able to kill the new instance %v", err)
				}
				err = bpfcfg.StartAllUserProgramsAndProbes()
				if err != nil {
					log.Error().Msgf("%v", err)
					mesg = mesg + fmt.Sprintf("not able to start all userprograms and probes: %v", err)
				}
				err = pidfile.CreatePID(bpfcfg.HostConfig.PIDFilename)
				if err != nil {
					log.Error().Msgf("%v", err)
					mesg = mesg + fmt.Sprintf("not able to create pid file: %v", err)
				}
				err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
				if err != nil {
					mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
				}
				statusCode = http.StatusInternalServerError
				log.Err(terr)
				return
			}
			break
		default:
			time.Sleep(time.Second)
		}

		st := <-NewProcessStatus
		if st == "Failed" {
			// write a function a to do cleanup of other process if necessary
			err = cmd.Process.Kill()
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to kill the new instance %v", err)
			}
			err = bpfcfg.StartAllUserProgramsAndProbes()
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to start all userprograms and probes: %v", err)
			}
			err = pidfile.CreatePID(bpfcfg.HostConfig.PIDFilename)
			if err != nil {
				log.Error().Msgf("%v", err)
				mesg = mesg + fmt.Sprintf("not able to create pid file: %v", err)
			}
			err = restart.RollBackSymlink(oldCfgPath, oldBinPath, oldVersion, t.Version, bpfcfg.HostConfig)
			if err != nil {
				mesg = mesg + fmt.Sprintf("rollback of symlink failed: %v", err)
			}
			statusCode = http.StatusInternalServerError
			return
		} else {
			log.Info().Msgf("doing exiting old process")
			models.CloseForRestart <- struct{}{}
		}
	}
}
