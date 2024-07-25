// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"net"
	"net/http"

	"github.com/l3af-project/l3afd/v2/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	BPFStartCount        *prometheus.CounterVec
	BPFStopCount         *prometheus.CounterVec
	BPFUpdateCount       *prometheus.CounterVec
	BPFUpdateFailedCount *prometheus.CounterVec
	BPFRunning           *prometheus.GaugeVec
	BPFStartTime         *prometheus.GaugeVec
	BPFMonitorMap        *prometheus.GaugeVec
)

func SetupMetrics(hostname, daemonName, metricsAddr string) {

	bpfStartCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "BPFStartCount",
			Help:      "The count of network functions started",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	BPFStartCount = bpfStartCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfStopCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "BPFStopCount",
			Help:      "The count of network functions stopped",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	BPFStopCount = bpfStopCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfUpdateCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "BPFUpdateCount",
			Help:      "The count of network functions updated",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	BPFUpdateCount = bpfUpdateCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfUpdateFailedCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "BPFUpdateFailedCount",
			Help:      "The count of Failed eBPF programs updates",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	BPFUpdateFailedCount = bpfUpdateFailedCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfRunningVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "BPFRunning",
			Help:      "This value indicates network functions is running or not",
		},
		[]string{"host", "ebpf_program", "version", "direction", "interface_name"},
	)

	if err := prometheus.Register(bpfRunningVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register BPFRunning metrics")
	}

	BPFRunning = bpfRunningVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfStartTimeVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "BPFStartTime",
			Help:      "This value indicates start time of the network function since unix epoch in seconds",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	if err := prometheus.Register(bpfStartTimeVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register BPFStartTime metrics")
	}

	BPFStartTime = bpfStartTimeVec.MustCurryWith(prometheus.Labels{"host": hostname})

	bpfMonitorMapVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "BPFMonitorMap",
			Help:      "This value indicates network function monitor counters",
		},
		[]string{"host", "ebpf_program", "map_name", "interface_name"},
	)

	if err := prometheus.Register(bpfMonitorMapVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register BPFMonitorMap metrics")
	}

	BPFMonitorMap = bpfMonitorMapVec.MustCurryWith(prometheus.Labels{"host": hostname})

	// Prometheus handler
	metricsHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	// Adding web endpoint
	go func() {
		// Expose the registered metrics via HTTP.
		if _, ok := models.AllNetListeners["stat_http"]; !ok {
			tcpAddr, err := net.ResolveTCPAddr("tcp", metricsAddr)
			if err != nil {
				fmt.Println("Error resolving TCP address:", err)
				return
			}
			listener, err := net.ListenTCP("tcp", tcpAddr)
			if err != nil {
				log.Fatal().Err(err).Msgf("Not able to create net Listen")
			}
			models.AllNetListeners["stat_http"] = listener
		}
		http.Handle("/metrics", metricsHandler)
		if err := http.Serve(models.AllNetListeners["stat_http"], nil); err != nil {
			log.Fatal().Err(err).Msgf("Failed to launch prometheus metrics endpoint")
		}
	}()
}

func Incr(counterVec *prometheus.CounterVec, ebpfProgram, direction, ifaceName string) {

	if counterVec == nil {
		log.Warn().Msg("Metrics: counter vector is nil and needs to be initialized before Incr")
		return
	}
	bpfCounter, err := counterVec.GetMetricWith(
		prometheus.Labels(map[string]string{
			"ebpf_program":   ebpfProgram,
			"direction":      direction,
			"interface_name": ifaceName,
		}),
	)
	if err != nil {
		log.Warn().Msgf("Metrics: unable to fetch counter with fields: ebpf_program: %s, direction: %s, interface_name: %s",
			ebpfProgram, direction, ifaceName)
		return
	}
	bpfCounter.Inc()
}

func Add(value float64, counterVec *prometheus.CounterVec, ebpfProgram, direction, ifaceName string) {

	if counterVec == nil {
		log.Warn().Msg("Metrics: counter vector is nil and needs to be initialized before Incr")
		return
	}
	bpfCounter, err := counterVec.GetMetricWith(
		prometheus.Labels(map[string]string{
			"ebpf_program":   ebpfProgram,
			"direction":      direction,
			"interface_name": ifaceName,
		}),
	)
	if err != nil {
		log.Warn().Msgf("Metrics: unable to fetch counter with fields: ebpf_program: %s, direction: %s, interface_name: %s",
			ebpfProgram, direction, ifaceName)
		return
	}
	bpfCounter.Add(value)
}

func Set(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}
	bpfGauge, err := gaugeVec.GetMetricWith(
		prometheus.Labels(map[string]string{
			"ebpf_program":   ebpfProgram,
			"direction":      direction,
			"interface_name": ifaceName,
		}),
	)
	if err != nil {
		log.Warn().Msgf("Metrics: unable to fetch gauge with fields: ebpf_program: %s, direction: %s, interface_name: %s",
			ebpfProgram, direction, ifaceName)
		return
	}
	bpfGauge.Set(value)
}

func SetValue(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, mapName, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before SetValue")
		return
	}
	bpfGauge, err := gaugeVec.GetMetricWith(
		prometheus.Labels(map[string]string{
			"ebpf_program":   ebpfProgram,
			"map_name":       mapName,
			"interface_name": ifaceName,
		}),
	)
	if err != nil {
		log.Warn().Msgf("Metrics: unable to fetch gauge with fields: ebpf_program: %s, map_name: %s, interface_name: %s",
			ebpfProgram, mapName, ifaceName)
		return
	}
	bpfGauge.Set(value)
}

func SetWithVersion(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, version, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}
	bpfGauge, err := gaugeVec.GetMetricWith(
		prometheus.Labels(map[string]string{
			"ebpf_program":   ebpfProgram,
			"version":        version,
			"direction":      direction,
			"interface_name": ifaceName,
		}),
	)
	if err != nil {
		log.Warn().Msgf("Metrics: unable to fetch gauge with fields: ebpf_program: %s, version: %s, direction: %s, interface_name: %s",
			ebpfProgram, version, direction, ifaceName)
		return
	}
	bpfGauge.Set(value)
}
