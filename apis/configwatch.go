// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !configs
// +build !configs

package apis

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/routes"
	"github.com/l3af-project/l3afd/signals"

	"github.com/rs/zerolog/log"
)

type Server struct {
	KFRTConfigs *kf.NFConfigs
	HostName    string
}

// @title L3AFD APIs
// @version 1.0
// @description Configuration APIs to deploy and get the details of the eBPF Programs on the node
// @host
// @BasePath /
func StartConfigWatcher(ctx context.Context, hostname, daemonName string, conf *config.Config, kfrtconfg *kf.NFConfigs) error {
	log.Info().Msgf("%s config server setup started on host %s", daemonName, hostname)

	s := &Server{
		KFRTConfigs: kfrtconfg,
		HostName:    hostname,
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, signals.ShutdownSignals...)
	go func() {
		<-term
		s.GracefulStop(conf.ShutdownTimeout)
		ctx.Done()
		log.Info().Msg("L3afd gracefulStop completed")
	}()

	go func() {
		r := routes.NewRouter(apiRoutes(ctx, kfrtconfg))
		r.Mount("/swagger", httpSwagger.WrapHandler)
		if err := http.ListenAndServe(conf.L3afConfigsRestAPIAddr, r); err != nil {
			log.Error().Err(err).Msgf("failed to http serve")
		}
	}()

	return nil
}

func (s *Server) GracefulStop(shutdownTimeout time.Duration) error {
	log.Info().Msg("L3afd graceful stop initiated")

	exitCode := 0
	if len(s.KFRTConfigs.IngressXDPBpfs) > 0 || len(s.KFRTConfigs.IngressTCBpfs) > 0 || len(s.KFRTConfigs.EgressTCBpfs) > 0 {
		ctx, cancelfunc := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelfunc()
		if err := s.KFRTConfigs.Close(ctx); err != nil {
			log.Error().Err(err).Msg("stopping all network functions failed")
			exitCode = 1
		}
	}

	os.Exit(exitCode)
	return nil
}
