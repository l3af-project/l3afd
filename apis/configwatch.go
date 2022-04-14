// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
// +build !configs
//

package apis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"time"

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/routes"
	"github.com/l3af-project/l3afd/signals"

	"github.com/rs/zerolog/log"
)

type Server struct {
	KFRTConfigs *kf.NFConfigs
	HostName    string
	l3afdServer *http.Server
}

func StartConfigWatcher(ctx context.Context, hostname, daemonName string, conf *config.Config, kfrtconfg *kf.NFConfigs) error {
	log.Info().Msgf("%s config server setup started on host %s", daemonName, hostname)

	s := &Server{
		KFRTConfigs: kfrtconfg,
		HostName:    hostname,
		l3afdServer: &http.Server{
			Addr: conf.L3afConfigsRestAPIAddr,
		},
	}

	term := make(chan os.Signal)
	signal.Notify(term, signals.ShutdownSignals...)
	go func() {
		<-term
		s.GracefulStop(conf.ShutdownTimeout)
		ctx.Done()
		log.Info().Msg("L3afd gracefulStop completed")
	}()

	go func() {
		r := routes.NewRouter(apiRoutes(ctx, kfrtconfg))
		s.l3afdServer.Handler = r

		// As per design discussion when mTLS flag is not set and not listening on loop back or localhost
		if !conf.MTLSEnabled && !isLoopback(conf.L3afConfigsRestAPIAddr) {
			conf.MTLSEnabled = true
		}

		if conf.MTLSEnabled {
			log.Info().Msgf("l3afd server listening with mTLS - %s ", conf.L3afConfigsRestAPIAddr)
			// Create a CA certificate pool and add client ca's to it
			caCert, err := ioutil.ReadFile(path.Join(conf.MTLSCertDir, conf.MTLSCACertFilename))
			if err != nil {
				log.Fatal().Err(err).Msgf("client CA %s file not found", conf.MTLSCACertFilename)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			// Create the TLS Config with the CA pool and enable Client certificate validation
			s.l3afdServer.TLSConfig = &tls.Config{
				ClientCAs:  caCertPool,
				ClientAuth: tls.RequireAndVerifyClientCert,
				MinVersion: conf.MTLSMinVersion,
			}

			if err := s.l3afdServer.ListenAndServeTLS(path.Join(conf.MTLSCertDir, conf.MTLSServerCertFilename), path.Join(conf.MTLSCertDir, conf.MTLSServerKeyFilename)); err != nil {
				log.Fatal().Err(err).Msgf("failed to start L3AFD server with mTLS enabled")
			}
		} else {
			log.Info().Msgf("l3afd server listening - %s ", conf.L3afConfigsRestAPIAddr)

			if err := s.l3afdServer.ListenAndServe(); err != nil {
				log.Fatal().Err(err).Msgf("failed to start L3AFD server")
			}
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

// isLoopbackAddr - Check for localhost or loop back address
func isLoopback(addr string) bool {

	if strings.Contains(addr, "localhost:") {
		return true
	}
	httpId := "://"
	if id := strings.Index(addr, httpId); id > -1 {
		addr = addr[id+len(httpId):]
	}
	if id := strings.LastIndex(addr, ":"); id > -1 {
		addr = addr[:id]
	}
	if ipAddr := net.ParseIP(addr); ipAddr != nil {
		return ipAddr.IsLoopback()
	}
	return false
}
