// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/rs/zerolog/log"
)

var (
	NFStartCount  *CounterValue
	NFStopCount   *CounterValue
	NFUpdateCount *CounterValue
	NFRunning     *GaugeValue
	NFStartTime   *GaugeValue
	NFMonitorMap  *GaugeValue
)

func SetupMetrics(hostname, daemonName, metricsAddr string) {
	ctx := context.Background()

	exporter, err := prometheus.New()
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to create Prometheus exporter")
	}
	provider := metric.NewMeterProvider(metric.WithReader(exporter))
	meter := provider.Meter("l3af-project/l3afd")

	baseAttributes := []attribute.KeyValue { attribute.Key("host").String(hostname) }

	metricName := daemonName + "_NFStartCount"
	startCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions started"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFStartCount")
	}
	NFStartCount = NewCounterValue(ctx, &startCount, metricName, baseAttributes)

	metricName = daemonName + "_NFStopCount"
	stopCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions stopped"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFStartCount")
	}
	NFStopCount = NewCounterValue(ctx, &stopCount, metricName, baseAttributes)

	metricName = daemonName + "_NFUpdateCount"
	updateCount, err := meter.Int64Counter(metricName, api.WithDescription("The count of network functions updated"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFUpdateCount")
	}
	NFUpdateCount = NewCounterValue(ctx, &updateCount, metricName, baseAttributes)

	gaugeValues := []*GaugeValue{}

	metricName = daemonName + "_NFRunning"
	runningGauge, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network functions is running or not"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFRunning")
	}
	NFRunning = NewGaugeValue(&runningGauge, metricName, baseAttributes)
	gaugeValues = append(gaugeValues, NFRunning)

	metricName = daemonName + "_NFStartTime"
	startTimeGauge, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates start time of the network function since unix epoch in seconds"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFStartTime")
	}
	NFStartTime = NewGaugeValue(&startTimeGauge, metricName, baseAttributes)
	gaugeValues = append(gaugeValues, NFStartTime)

	metricName = daemonName + "_NFMonitorMap"
	monitorMapGauge, err := meter.Float64ObservableGauge(metricName, api.WithDescription("This value indicates network function monitor counters"))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create NFMonitorMap")
	}
	NFMonitorMap = NewGaugeValue(&monitorMapGauge, metricName, baseAttributes)
	gaugeValues = append(gaugeValues, NFMonitorMap)

	// Gauge value update is done through callback
	for _, gaugeVal := range gaugeValues {
		gauge := gaugeVal.Gauge
		_, err = meter.RegisterCallback(func(_ context.Context, o api.Observer) error {
			o.ObserveFloat64(*gauge, gaugeVal.GetValue(), gaugeVal.GetMeasurementOptions())
			return nil
		}, *gauge)

		if err != nil {
			log.Warn().Err(err).Msgf("Failed to update metric value for %s", gaugeVal.MetricName)
		}
	}

	// Adding web endpoint
	go func() {
		// Expose the registered metrics via HTTP.
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			log.Fatal().Err(err).Msg("Failed to launch prometheus metrics endpoint")
		}
	}()
}

func Incr(counterVec *CounterValue, ebpfProgram, direction, ifaceName string) {

	if counterVec == nil {
		log.Warn().Msg("Metrics: counter vector is nil and needs to be initialized before Incr")
		return
	}

	updatedAttributes := []attribute.KeyValue {
		attribute.String("ebpf_program", ebpfProgram),
		attribute.String("direction", direction),
		attribute.String("ifaceName", ifaceName),
	}

	counterVec.Increment(updatedAttributes)
}

func Set(value float64, gaugeVec *GaugeValue, ebpfProgram, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}

	updatedAttributes := []attribute.KeyValue {
		attribute.String("ebpf_program", ebpfProgram),
		attribute.String("direction", direction),
		attribute.String("ifaceName", ifaceName),
	}

	gaugeVec.SetValue(value, updatedAttributes)
}

func SetValue(value float64, gaugeVec *GaugeValue, ebpfProgram, mapName, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before SetValue")
		return
	}

	updatedAttributes := []attribute.KeyValue {
		attribute.String("ebpf_program", ebpfProgram),
		attribute.String("map_name", mapName),
		attribute.String("interface_name", ifaceName),
	}

	gaugeVec.SetValue(value, updatedAttributes)
}

func SetWithVersion(value float64, gaugeVec *GaugeValue, ebpfProgram, version, direction, ifaceName string) {

	if gaugeVec == nil {
		log.Warn().Msg("Metrics: gauge vector is nil and needs to be initialized before Set")
		return
	}

	updatedAttributes := []attribute.KeyValue {
		attribute.String("ebpf_program", ebpfProgram),
		attribute.String("version", version),
		attribute.String("direction", direction),
		attribute.String("interface_name", ifaceName),
	}

	gaugeVec.SetValue(value, updatedAttributes)
}
