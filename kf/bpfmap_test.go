// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

package kf

import (
	"container/ring"
	"reflect"
	"testing"
)

var TestValues *ring.Ring = ring.New(10)

func SetupTestValues() {
	a := [10]float64{8, 10, 6, 23, 4, 53, 32, 8, 2, 7}
	v := TestValues
	for i := 0; i < TestValues.Len(); i++ {
		v.Value = a[i]
		v = v.Next()
	}
}
func TestMetricsBPFMapMaxValue(t *testing.T) {
	type args struct {
		key        int
		Values     *ring.Ring
		aggregator string
	}
	SetupTestValues()
	tests := []struct {
		name    string
		args    args
		want    float64
		wantErr bool
	}{
		{
			name:    "max-rate",
			args:    args{key: 0, Values: TestValues, aggregator: "max-rate"},
			want:    53,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metricsMap := &MetricsBPFMap{
				Values:     TestValues,
				key:        0,
				aggregator: tt.args.aggregator,
				lastValue:  0,
			}
			got := (metricsMap.MaxValue())
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MaxValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetricsBPFMapAvgValue(t *testing.T) {
	type args struct {
		key        int
		Values     *ring.Ring
		aggregator string
	}
	SetupTestValues()
	tests := []struct {
		name    string
		args    args
		want    float64
		wantErr bool
	}{
		{
			name:    "avg",
			args:    args{key: 0, Values: TestValues, aggregator: "avg"},
			want:    15.3,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metricsMap := &MetricsBPFMap{
				Values:     TestValues,
				key:        0,
				aggregator: tt.args.aggregator,
				lastValue:  0,
			}
			got := (metricsMap.AvgValue())
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AvgValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
