// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
//go:build !configs
// +build !configs

package apis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/l3af-project/l3afd/config"
	"github.com/l3af-project/l3afd/kf"
	"github.com/l3af-project/l3afd/routes"
	"github.com/l3af-project/l3afd/signals"

	_ "github.com/l3af-project/l3afd/docs"

	"github.com/rs/zerolog/log"
)

type Server struct {
	KFRTConfigs   *kf.NFConfigs
	HostName      string
	l3afdServer   *http.Server
	CaCertPool    *x509.CertPool
	SANMatchRules []string
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
		l3afdServer: &http.Server{
			Addr: conf.L3afConfigsRestAPIAddr,
		},
		SANMatchRules: conf.MTLSSANMatchRules,
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
		if conf.SwaggerApiEnabled {
			r.Mount("/swagger", httpSwagger.WrapHandler)
		}

		s.l3afdServer.Handler = r

		// As per design discussion when mTLS flag is not set and not listening on loopback or localhost
		if !conf.MTLSEnabled && !isLoopback(conf.L3afConfigsRestAPIAddr) && conf.Environment == config.ENV_PROD {
			conf.MTLSEnabled = true
		}

		if conf.MTLSEnabled {
			log.Info().Msgf("l3afd server listening with mTLS - %s ", conf.L3afConfigsRestAPIAddr)
			// Create a CA certificate pool and add client ca's to it
			caCert, err := os.ReadFile(path.Join(conf.MTLSCertDir, conf.MTLSCACertFilename))
			if err != nil {
				log.Fatal().Err(err).Msgf("client CA %s file not found", conf.MTLSCACertFilename)
			}

			s.CaCertPool, _ = x509.SystemCertPool()
			if s.CaCertPool == nil {
				s.CaCertPool = x509.NewCertPool()
			}
			if ok := s.CaCertPool.AppendCertsFromPEM(caCert); !ok {
				log.Warn().Msgf("No client certs appended for mTLS")
			}
			serverCertFile := path.Join(conf.MTLSCertDir, conf.MTLSServerCertFilename)
			serverKeyFile := path.Join(conf.MTLSCertDir, conf.MTLSServerKeyFilename)
			serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
			if err != nil {
				log.Fatal().Err(err).Msgf("failure loading certs")
			}
			// build server config
			s.l3afdServer.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
					serverConf := &tls.Config{
						Certificates:          []tls.Certificate{serverCert},
						MinVersion:            tls.VersionTLS12,
						ClientAuth:            tls.RequireAndVerifyClientCert,
						ClientCAs:             s.CaCertPool,
						VerifyPeerCertificate: s.getClientValidator(hi),
					}
					return serverConf, nil
				},
			}

			cpb, _ := pem.Decode(caCert)
			cert, err := x509.ParseCertificate(cpb.Bytes)
			if err != nil {
				log.Fatal().Err(err).Msgf("error in parsing tls certificate : %v", conf.MTLSCACertFilename)
			}
			expiry := cert.NotAfter
			start := cert.NotBefore
			go func() {
				period := time.Hour * 24
				ticker := time.NewTicker(period)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						MonitorTLS(start, expiry, conf)
					case <-ctx.Done():
						return
					}
				}
			}()

			if err := s.l3afdServer.ListenAndServeTLS(serverCertFile, serverKeyFile); err != nil {
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

// isLoopback - Check for localhost or loopback address
func isLoopback(addr string) bool {

	if strings.Contains(addr, "localhost:") {
		return true
	}
	if id := strings.LastIndex(addr, ":"); id > -1 {
		addr = addr[:id]
	}
	if ipAddr := net.ParseIP(addr); ipAddr != nil {
		return ipAddr.IsLoopback()
	}
	// :port scenario
	return true
}

func MonitorTLS(start time.Time, expiry time.Time, conf *config.Config) {
	todayDate := time.Now()
	expiryDate := expiry
	startDate := start
	diff := expiryDate.Sub(todayDate)
	remainingHoursToStart := todayDate.Sub(startDate)
	limit := conf.MTLSCertExpiryWarningDays * 24
	remainingHoursToExpire := int(diff.Hours())
	if remainingHoursToStart > 0 {
		log.Fatal().Msgf("tls certificate start from : %v", startDate)
	}
	if remainingHoursToExpire <= limit {
		if remainingHoursToExpire < 0 {
			log.Fatal().Msgf("tls certificate is expired on : %v", expiryDate)
		} else {
			log.Warn().Msgf("tls certificate will expire in %v days", int64(remainingHoursToExpire/24))
		}
	}
}

func (s *Server) getClientValidator(helloInfo *tls.ClientHelloInfo) func([][]byte, [][]*x509.Certificate) error {

	log.Debug().Msgf("Inside get client validator - %v", helloInfo.Conn.RemoteAddr())
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Verifying client certs with root ca
		opts := x509.VerifyOptions{
			Roots:         s.CaCertPool,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		_, err := verifiedChains[0][0].Verify(opts)
		if err != nil {
			log.Error().Err(err).Msgf("certs verification failed")
			return err
		}

		log.Debug().Msgf("validating with SAN match rules - %s", s.SANMatchRules)
		if len(s.SANMatchRules) == 0 {
			return nil
		}
		for _, dnsName := range verifiedChains[0][0].DNSNames {
			if !validHostname(dnsName, true) {
				continue
			}
			dnsName = toLowerCaseASCII(dnsName)
			for _, sanMatchRule := range s.SANMatchRules {
				sanMatchRule = toLowerCaseASCII(sanMatchRule)
				if matchExactly(dnsName, sanMatchRule) {
					log.Debug().Msgf("Successfully matched matchExactly cert dns %s SANMatchRule %s", dnsName, sanMatchRule)
					return nil
				} else if matchHostnamesWithRegexp(dnsName, sanMatchRule) {
					log.Debug().Msgf("Successfully matched matchHostnamesWithRegexp cert dns %s SANMatchRule %s", dnsName, sanMatchRule)
					return nil
				}
			}
		}

		err = errors.New("certs verification with SAN match not found")
		log.Error().Err(err).Msgf("SAN match rules %s", s.SANMatchRules)
		return err
	}
}

// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

// matchExactly - match hostnames
func matchExactly(hostA, hostB string) bool {
	// Here checking hostB (i.e. sanMatchRule) is valid hostname and not regex/pattern
	if !validHostname(hostB, false) {
		return false
	}
	return hostA == hostB
}

// matchHostnamesWithRegexp - To match the san rules with regexp
func matchHostnamesWithRegexp(dnsName, sanMatchRule string) bool {
	defer func() bool {
		if err := recover(); err != nil {
			log.Warn().Msgf("panic occurred: %v", err)
		}
		return false
	}()
	if len(dnsName) == 0 || len(sanMatchRule) == 0 {
		return false
	}
	re := regexp.MustCompile(sanMatchRule)

	return re.MatchString(dnsName)
}
