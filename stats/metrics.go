// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"net/http"

	"tbd/go-shared/logs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	NFStartCount  *prometheus.CounterVec
	NFStopCount   *prometheus.CounterVec
	NFUpdateCount *prometheus.CounterVec
	NFRunning     *prometheus.GaugeVec
	NFStartTime   *prometheus.GaugeVec
	NFMointorMap  *prometheus.GaugeVec
)

func SetupMetrics(hostname, daemonName, metricsAddr string) {

	nfStartCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFStartCount",
			Help:      "The count of network functions started",
		},
		[]string{"host", "network_function", "direction"},
	)

	NFStartCount = nfStartCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfStopCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFStopCount",
			Help:      "The count of network functions stopped",
		},
		[]string{"host", "network_function", "direction"},
	)

	NFStopCount = nfStopCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfUpdateCountVec := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: daemonName,
			Name:      "NFUpdateCount",
			Help:      "The count of network functions updated",
		},
		[]string{"host", "network_function", "direction"},
	)

	NFUpdateCount = nfUpdateCountVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfRunningVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFRunning",
			Help:      "This value indicates network functions is running or not",
		},
		[]string{"host", "network_function", "direction"},
	)

	logs.IfWarningLogf(prometheus.Register(nfRunningVec), "Failed to register NFRunning metrics")

	NFRunning = nfRunningVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfStartTimeVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFStartTime",
			Help:      "This value indicates start time of the network function since unix epoch in seconds",
		},
		[]string{"host", "network_function", "direction"},
	)

	logs.IfWarningLogf(prometheus.Register(nfStartTimeVec), "Failed to register NFStartTime metrics")

	NFStartTime = nfStartTimeVec.MustCurryWith(prometheus.Labels{"host": hostname})

	nfMonitorMapVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: daemonName,
			Name:      "NFMonitorMap",
			Help:      "This value indicates network function monitor counters",
		},
		[]string{"host", "network_function", "map_name"},
	)

	logs.IfWarningLogf(prometheus.Register(nfMonitorMapVec), "Failed to register NFMonitorMap metrics")

	NFMointorMap = nfMonitorMapVec.MustCurryWith(prometheus.Labels{"host": hostname})

	// Prometheus handler
	metricsHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	// Adding web endpoint
	go func() {
		// Expose the registered metrics via HTTP.
		http.Handle("/metrics", metricsHandler)
		logs.IfFatalLogf(http.ListenAndServe(metricsAddr, nil), "Failed to launch prometheus metrics endpoint")
	}()
}

func Incr(counterVec *prometheus.CounterVec, networkFunction, direction string) {

	if counterVec == nil {
		logs.Warningf("Metrics: counter vector is nil and needs to be initialized")
		return
	}
	if nfCounter, err := counterVec.GetMetricWithLabelValues(networkFunction, direction); err == nil {
		nfCounter.Inc()
	}
}

func Set(value float64, gaugeVec *prometheus.GaugeVec, networkFunction, direction string) {

	if gaugeVec == nil {
		logs.Warningf("Metrics: gauge vector is nil and needs to be initialized")
		return
	}
	if nfGauge, err := gaugeVec.GetMetricWithLabelValues(networkFunction, direction); err == nil {
		nfGauge.Set(value)
	}
}

func SetValue(value float64, gaugeVec *prometheus.GaugeVec, networkFunction, mapName string) {

	if gaugeVec == nil {
		logs.Warningf("Metrics: gauge vector is nil and needs to be initialized")
		return
	}
	if nfGauge, err := gaugeVec.GetMetricWithLabelValues(networkFunction, mapName); err == nil {
		nfGauge.Set(value)
	}
}
