// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0
//
// +build !configs
//

package kf

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/l3af-project/l3afd/config"
	pb "github.com/l3af-project/l3afd/proto/gen/v1/l3afdconfig"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

type Server struct {
	KFRTConfigs *NFConfigs
	HostName    string
	GrpcSrv     *grpc.Server
	HttpLis     net.Listener
	Status      pb.HealthCheckResponse_ServiceStatus
	pb.UnimplementedL3AfConfiguratorServer
}

var kaep = keepalive.EnforcementPolicy{
	MinTime: 5 * time.Second, // If a client pings more than once every 5 seconds, terminate the connection
}

func (s *Server) UpdateConfig(ctx context.Context, req *pb.L3AfdConfigRequest) (*pb.L3AfdConfigResponse, error) {

	if req == nil {
		log.Error().Msg("request object is nil in L3AfdConfigRequest")
		return nil, status.Errorf(codes.Internal, "request object is nil")
	}

	if len(req.Key) < 1 {
		log.Error().Msg("length of the key is empty")
		return nil, status.Errorf(codes.Internal, "request key or value is empty")
	}

	if req.Key != s.HostName {
		log.Debug().Msgf("Key %q doesn't match hostname %q", req.Key, s.HostName)
		return nil, status.Errorf(codes.NotFound, "request key doesn't match the hostname")
	}

	if len(req.Value) < 1 {
		if err := s.KFRTConfigs.HandleDeleted([]byte(req.Key)); err != nil {
			log.Error().Err(err).Msg("HandleDeleted failed")
		}
		return &pb.L3AfdConfigResponse{}, status.Errorf(codes.OK, "")
	}

	if err := s.KFRTConfigs.HandleUpdated([]byte(req.Key), []byte(req.Value)); err != nil {
		return &pb.L3AfdConfigResponse{
			Error: "Handle Update is failed ",
		}, status.Errorf(codes.Internal, err.Error())
	}
	return &pb.L3AfdConfigResponse{}, status.Errorf(codes.OK, "")
}

func (s *Server) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	resp := &pb.HealthCheckResponse{Status: s.Status}

	if s.Status == pb.HealthCheckResponse_STARTED {
		s.Status = pb.HealthCheckResponse_READY
	}

	return resp, status.Errorf(codes.OK, "")
}

func StartConfigWatcher(ctx context.Context, hostname, daemonName string, conf *config.Config, kfrtconfg *NFConfigs) error {
	log.Info().Msgf("%s config server setup started on host %s", daemonName, hostname)

	s := &Server{
		KFRTConfigs: kfrtconfg,
		HostName:    hostname,
		Status:      pb.HealthCheckResponse_STARTED,
	}

	term := make(chan os.Signal)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-term
		s.GracefulStop(conf.ShutdownTimeout)
		ctx.Done()
		log.Info().Msg("L3afd gracefulStop completed")
	}()

	go func() {
		lis, err := net.Listen("tcp", conf.L3afConfigsgRPCAddr)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to listen on gRPC addr %s", conf.L3afConfigsgRPCAddr)
		}

		s.GrpcSrv = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep))
		pb.RegisterL3AfConfiguratorServer(s.GrpcSrv, s)

		if err := s.GrpcSrv.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("failed to serve")
		}
	}()

	go func() {
		var err error
		s.HttpLis, err = net.Listen("tcp", conf.L3afConfigsRestAPIAddr)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to listen port %s", conf.L3afConfigsRestAPIAddr)
		}
		mux := runtime.NewServeMux()
		dialOptions := []grpc.DialOption{grpc.WithInsecure()}
		pb.RegisterL3AfConfiguratorHandlerFromEndpoint(ctx, mux, conf.L3afConfigsgRPCAddr, dialOptions)

		if err := http.Serve(s.HttpLis, mux); err != nil {
			log.Error().Err(err).Msgf("failed to http serve")
		}
	}()

	log.Info().Msg("gRPC server setup completed")
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

	if err := s.HttpLis.Close(); err != nil {
		log.Error().Err(err).Msgf("error on http listener close")
		exitCode = 1
	}
	s.GrpcSrv.GracefulStop()
	os.Exit(exitCode)
	return nil
}
