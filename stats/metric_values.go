package stats

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
)

type metricAttributes struct {
	baseAttribCount		int
	MetricName			string
	Attribs 			[]attribute.KeyValue
}

func newMetricAttribs(metricName string, baseAttribs []attribute.KeyValue) *metricAttributes {
	retval := metricAttributes {
		MetricName: metricName,
		Attribs: make([]attribute.KeyValue, len(baseAttribs)),
	}

	copy(retval.Attribs, baseAttribs)
	return &retval
}

func (metricAttribs *metricAttributes) getMeasurementOptions(attribsToInclude []attribute.KeyValue) api.MeasurementOption {
	if attribsToInclude != nil {
		updatedAttribs := append(metricAttribs.Attribs, attribsToInclude...)
		return api.WithAttributes(updatedAttribs...)
	}

	return api.WithAttributes(metricAttribs.Attribs...)
}

func (metricAttribs *metricAttributes) setAttributes(newAttribValues []attribute.KeyValue) {
	metricAttribs.Attribs = metricAttribs.Attribs[:metricAttribs.baseAttribCount]
	metricAttribs.Attribs = append(metricAttribs.Attribs, newAttribValues...)
}

// =====================================================
type GaugeValue struct {
	Gauge				*api.Float64ObservableGauge
	Value				float64
	mutex				sync.RWMutex
	*metricAttributes
}

func NewGaugeValue(gauge *api.Float64ObservableGauge, metricName string, attribs []attribute.KeyValue) *GaugeValue {
	return &GaugeValue {
		Gauge: gauge,
		Value: 0,
		metricAttributes: newMetricAttribs(metricName, attribs),
	}
}

func (gaugeValue *GaugeValue) GetMeasurementOptions() api.MeasurementOption {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	return gaugeValue.getMeasurementOptions(nil)
}

func (gaugeValue *GaugeValue) SetValue(val float64, attribs []attribute.KeyValue) {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	gaugeValue.metricAttributes.setAttributes(attribs)
	gaugeValue.Value = val
}

func (gaugeValue *GaugeValue) GetValue() float64 {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	return gaugeValue.Value
}

// =====================================================
type CounterValue struct {
	Ctx 				context.Context
	Counter 			*api.Int64Counter
	Value 				int64
	*metricAttributes
}

func NewCounterValue(ctx context.Context, counter *api.Int64Counter, metricName string, attribs []attribute.KeyValue) *CounterValue {
	return &CounterValue{
		Ctx: ctx,
		Counter: counter,
		Value: 0,
		metricAttributes: newMetricAttribs(metricName, attribs),
	}
}

func (counterValue *CounterValue) Increment(attribs []attribute.KeyValue) {
	(*(counterValue.Counter)).Add(counterValue.Ctx, 1, counterValue.getMeasurementOptions(attribs))
}
