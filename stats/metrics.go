// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	NFStartCount  *prometheus.CounterVec
	NFStopCount   *prometheus.CounterVec
	NFUpdateCount *prometheus.CounterVec
	NFRunning     *prometheus.GaugeVec
	NFStartTime   *prometheus.GaugeVec
	NFMonitorMap  *prometheus.GaugeVec
)

func SetupMetrics(hostname, daemonName, metricsAddr string) {

	nfStartCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFStartCount",
			Help:      "The count of network functions started",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	NFStartCount = nfStartCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfStopCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFStopCount",
			Help:      "The count of network functions stopped",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	NFStopCount = nfStopCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfUpdateCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFUpdateCount",
			Help:      "The count of network functions updated",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	NFUpdateCount = nfUpdateCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfRunningVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFRunning",
			Help:      "This value indicates network functions is running or not",
		},
		[]string{"host", "ebpf_program", "version", "direction", "interface_name"},
	)

	if err := prometheus.Register(nfRunningVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register NFRunning metrics")
	}

	NFRunning = nfRunningVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfStartTimeVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFStartTime",
			Help:      "This value indicates start time of the network function since unix epoch in seconds",
		},
		[]string{"host", "ebpf_program", "direction", "interface_name"},
	)

	if err := prometheus.Register(nfStartTimeVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register NFStartTime metrics")
	}

	NFStartTime = nfStartTimeVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfMonitorMapVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFMonitorMap",
			Help:      "This value indicates network function monitor counters",
		},
		[]string{"host", "ebpf_program", "map_name", "interface_name"},
	)

	if err := prometheus.Register(nfMonitorMapVec); err != nil {
		log.Warn().Err(err).Msg("Failed to register NFMonitorMap metrics")
	}

	NFMonitorMap = nfMonitorMapVec.MustCurryWith(prometheus.Labels{"host": hostname})

	// Prometheus handler
	metricsHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	// Adding web endpoint
	go func() {
		// Expose the registered metrics via HTTP.
		http.Handle("/metrics", metricsHandler)
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			log.Fatal().Err(err).Msgf("Failed to launch prometheus metrics endpoint")
		}
	}()
}

func Incr(counterVec *prometheus.CounterVec, ebpfProgram, direction, ifaceName string) {

	if counterVec == nil {
		log.Warn().Msg("Metrics: counter vector is nil and needs to be initialized before Incr")
		return
	}
	nfCounter, err := counterVec.GetMetricWith(
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
	nfCounter.Inc()
}

func Set(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}
	nfGauge, err := gaugeVec.GetMetricWith(
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
	nfGauge.Set(value)
}

func SetValue(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, mapName, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before SetValue")
		return
	}
	nfGauge, err := gaugeVec.GetMetricWith(
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
	nfGauge.Set(value)
}

func SetWithVersion(value float64, gaugeVec *prometheus.GaugeVec, ebpfProgram, version, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}
	nfGauge, err := gaugeVec.GetMetricWith(
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
	nfGauge.Set(value)
}
