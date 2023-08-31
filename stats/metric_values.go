package stats

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
)

type metricAttributes struct {
	baseAttributeCount  int
	MetricName          string
	Attributes          []attribute.KeyValue
}

func newMetricAttributes(metricName string, baseAttributes []attribute.KeyValue) *metricAttributes {
	retval := metricAttributes {
		MetricName: metricName,
		Attributes: make([]attribute.KeyValue, len(baseAttributes)),
	}

	copy(retval.Attributes, baseAttributes)
	return &retval
}

func (metricAttributes *metricAttributes) getMeasurementOptions(attributesToInclude []attribute.KeyValue) api.MeasurementOption {
	if attributesToInclude != nil {
		updatedAttributes := append(metricAttributes.Attributes, attributesToInclude...)
		return api.WithAttributes(updatedAttributes...)
	}

	return api.WithAttributes(metricAttributes.Attributes...)
}

func (metricAttributes *metricAttributes) setAttributes(newAttribValues []attribute.KeyValue) {
	metricAttributes.Attributes = metricAttributes.Attributes[:metricAttributes.baseAttributeCount]
	metricAttributes.Attributes = append(metricAttributes.Attributes, newAttribValues...)
}

// =====================================================
type GaugeValue struct {
	Gauge				*api.Float64ObservableGauge
	Value				float64
	mutex				sync.RWMutex
	*metricAttributes
}

func NewGaugeValue(gauge *api.Float64ObservableGauge, metricName string, attributes []attribute.KeyValue) *GaugeValue {
	return &GaugeValue {
		Gauge: gauge,
		Value: 0,
		metricAttributes: newMetricAttributes(metricName, attributes),
	}
}

func (gaugeValue *GaugeValue) GetMeasurementOptions() api.MeasurementOption {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	return gaugeValue.getMeasurementOptions(nil)
}

func (gaugeValue *GaugeValue) SetValue(val float64, attributes []attribute.KeyValue) {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	gaugeValue.metricAttributes.setAttributes(attributes)
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

func NewCounterValue(ctx context.Context, counter *api.Int64Counter, metricName string, attributes []attribute.KeyValue) *CounterValue {
	return &CounterValue{
		Ctx: ctx,
		Counter: counter,
		Value: 0,
		metricAttributes: newMetricAttributes(metricName, attributes),
	}
}

func (counterValue *CounterValue) Increment(attributes []attribute.KeyValue) {
	(*(counterValue.Counter)).Add(counterValue.Ctx, 1, counterValue.getMeasurementOptions(attributes))
}
