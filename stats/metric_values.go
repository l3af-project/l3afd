package stats

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
)

type MetricAttributes struct {
	baseAttribCount		int
	mutex				sync.RWMutex
	MetricName			string
	Attribs 			[]attribute.KeyValue
}

func NewMetricAttribs(metricName string, baseAttribs []attribute.KeyValue) *MetricAttributes {
	retval := MetricAttributes {
		MetricName: metricName,
		Attribs: make([]attribute.KeyValue, len(baseAttribs) + 5),
	}

	copy(retval.Attribs, baseAttribs)
	return &retval
}

func (metricAttribs *MetricAttributes) GetMeasurementOptions() api.MeasurementOption {
	metricAttribs.mutex.Lock()
	defer metricAttribs.mutex.Unlock()
	
	return api.WithAttributes(metricAttribs.Attribs...)
}

func (metricAttribs *MetricAttributes) SetAttributes(attribValuesToUpdate map[string]string) {
	metricAttribs.mutex.Lock()
	defer metricAttribs.mutex.Unlock()
	
	metricAttribs.Attribs = metricAttribs.Attribs[:metricAttribs.baseAttribCount]
	for name, value := range attribValuesToUpdate {
		metricAttribs.Attribs = append(metricAttribs.Attribs, attribute.Key(name).String(value))
	}
}

// =====================================================
type GaugeValue struct {
	Gauge				*api.Float64ObservableGauge
	Value				float64
	*MetricAttributes
}

func NewGaugeValue(gauge *api.Float64ObservableGauge, metricName string, attribs []attribute.KeyValue) *GaugeValue {
	return &GaugeValue {
		Gauge: gauge,
		Value: 0,
		MetricAttributes: NewMetricAttribs(metricName, attribs),
	}
}

func (gaugeValue *GaugeValue) GetValue() float64 {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()

	return gaugeValue.Value
}

func (gaugeValue *GaugeValue) SetValue(val float64) {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()
	
	gaugeValue.Value = val
}

// =====================================================
type CounterValue struct {
	Ctx 				context.Context
	Counter 			*api.Int64Counter
	Value 				int64
	*MetricAttributes

}

func NewCounterValue(ctx context.Context, counter *api.Int64Counter, metricName string, attribs []attribute.KeyValue) *CounterValue {
	return &CounterValue{
		Ctx: ctx,
		Counter: counter,
		Value: 0,
		MetricAttributes: NewMetricAttribs(metricName, attribs),
	}
}

func (counterValue *CounterValue) Increment() {
	(*(counterValue.Counter)).Add(counterValue.Ctx, 1, counterValue.GetMeasurementOptions())
}
