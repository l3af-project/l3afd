// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package pidfile

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

func CheckPIDConflict(pidFilename string) error {
	log.Info().Msgf("Checking for another already running instance (using PID file \"%s\")...", pidFilename)
	pidFileContent, err := os.ReadFile(pidFilename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info().Msgf("OK, no PID file already exists at %s.", pidFilename)
			return nil
		}
		return fmt.Errorf("could not open PID file: %s, please manually remove; error: %v", pidFilename, err)
	}
	if len(pidFileContent) < 1 {
		log.Warn().Msgf("PID file already exists at %s, but it is empty... ignoring.", pidFilename)
		return nil
	}
	oldPIDString := string(pidFileContent)
	oldPID, err := strconv.Atoi(oldPIDString)
	if err != nil {
		return fmt.Errorf("PID file: %s, contained value: %s, which could not be parsed; error: %v", pidFilename, oldPIDString, err)
	}

	log.Info().Msgf("Found PID file with PID: %d; checking if it is this process: PID: %d", oldPID, os.Getpid())
	if oldPID == os.Getpid() {
		log.Warn().Msgf("PID file already exists at %s, but it contains the current PID(%d)... ignoring.", pidFilename, oldPID)
		return nil
	}

	log.Info().Msgf("Found PID file with PID: %s; checking if process is running...", oldPIDString)
	process, err := os.FindProcess(oldPID)
	if err == nil {
		//On Linux, if sig is 0, then no signal is sent, but error checking is still performed;
		//this can be used to check for the existence of a process ID or process  group ID.
		//See: man 2 kill
		err = process.Signal(syscall.Signal(0))
	}
	if err != nil {
		log.Info().Msgf("Process was not running, removing PID file.")
		if err = RemovePID(pidFilename); err != nil {
			return fmt.Errorf("removal failed, please manually remove; err: %v", err)
		}
		return nil
	}

	log.Info().Msgf("Process with PID: %s; is running. Comparing process names to ensure it is a true conflict.", oldPIDString)
	selfProcName, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		return fmt.Errorf("could not read this processes command name from the proc filesystem; err: %v", err)
	}
	conflictProcName, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", oldPID))
	if err != nil {
		return fmt.Errorf("could not read old processes (PID: %s) command name from the proc filesystem; error: %v", oldPIDString, err)
	}
	if string(selfProcName) != string(conflictProcName) {
		log.Info().Msgf("Old process had command name: %q, not %q, removing PID file.", conflictProcName, selfProcName)
		if err = RemovePID(pidFilename); err != nil {
			return fmt.Errorf("removal failed, please manually remove; error: %v", err)
		}
		return nil
	}

	return fmt.Errorf("a previous instance of this process (%s) is running with ID %s; please shutdown this process before running", selfProcName, oldPIDString)
}

func CreatePID(pidFilename string) error {
	PID := os.Getpid()
	log.Info().Msgf("Writing process ID %d to %s...", PID, pidFilename)
	if err := os.WriteFile(pidFilename, []byte(strconv.Itoa(PID)), 0640); err != nil {
		return fmt.Errorf("could not write process ID to file: \"%s\"; error: %v", pidFilename, err)
	}
	return nil
}

func RemovePID(pidFilename string) error {
	err := os.RemoveAll(pidFilename)
	if err != nil {
		err = fmt.Errorf("could not remove PID file: %s; error: %v", pidFilename, err)
	}
	return err
}

func SetupGracefulShutdown(shutdownHandler func() error, shutdownHandlerTimeout time.Duration, pidFilename string) {
	const defaultShutdownTO = time.Second * 10
	if shutdownHandlerTimeout < 1 {
		log.Warn().Msgf("GracefulShutdown: No shutdown timeout was provided! Using %s.", defaultShutdownTO)
		shutdownHandlerTimeout = defaultShutdownTO
	}

	//We must use a buffered channel or risk missing the signal if we're not
	//ready to receive when the signal is sent.
	interruptCh := make(chan os.Signal, 1)
	signal.Notify(interruptCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)

	//Start worker that listens for shutdown signal and handles it
	go func() {
		interrupt := <-interruptCh
		exitCode := 0

		if shutdownHandler != nil { //Run shutdown handler
			log.Info().Msgf("GracefulShutdown: Received shutdown signal: %s, waiting for shutdown handler to execute (will timeout after %s)...", interrupt, shutdownHandlerTimeout)
			handlerDoneCh := make(chan struct{})
			go func() {
				if err := shutdownHandler(); err != nil {
					log.Error().Err(err).Msgf("GracefulShutdown: Shutdown handler returned error")
					exitCode = 1
				}
				handlerDoneCh <- struct{}{}
			}()
			select {
			case <-handlerDoneCh:
				log.Info().Msgf("GracefulShutdown: Shutdown handler execution complete. Shutting down...")
			case <-time.After(shutdownHandlerTimeout):
				log.Error().Msgf("GracefulShutdown: Shutdown handler execution timed-out after %s! Shutting down...", shutdownHandlerTimeout)
				exitCode = 1
			}
		} else {
			log.Info().Msgf("GracefulShutdown: Received shutdown signal: %s, shutting down...", interrupt)
		}

		if pidFilename != "" {
			if err := RemovePID(pidFilename); err != nil {
				log.Warn().Err(err).Msgf("Could not cleanup PID file")
			}
		}
		log.Info().Msgf("Shutdown now.")
		os.Exit(exitCode)
	}()
}
