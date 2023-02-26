package stats

import (
	"context"
	"log"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	ebpfNamespace = "ebpf_bumblebee_io"
)

func NewPrometheusMetricsProvider(ctx context.Context, registry *prometheus.Registry) MetricsProvider {
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	return &metricsProvider{
		registry: registry,
	}
}

type MetricsProvider interface {
	NewSetCounter(name string, additionalLabels map[string]string, labelKeys ...string) SetInstrument
	NewIncrementCounter(name string, additionalLabels map[string]string, labelKeys ...string) IncrementInstrument
	NewGauge(name string, additionalLabels map[string]string, labelKeys ...string) SetInstrument
}

type Cleaner interface {
	Clean()
}

type IncrementInstrument interface {
	Cleaner
	Increment(ctx context.Context, labels map[string]string)
}

type SetInstrument interface {
	Cleaner
	Set(ctx context.Context, val int64, labels map[string]string)
}

type metricsProvider struct {
	registry prometheus.Registerer
}

func (m *metricsProvider) NewSetCounter(name string, additionalLabels map[string]string, labelKeys ...string) SetInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   ebpfNamespace,
		Name:        name,
		ConstLabels: additionalLabels,
	}, labelKeys)

	m.register(counter)
	return &setCounter{
		deregisterFunc: m.registry.Unregister,
		counter:        counter,
		counterMap:     map[uint64]int64{},
	}
}

func (m *metricsProvider) NewIncrementCounter(name string, additionalLabels map[string]string, labelKeys ...string) IncrementInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   ebpfNamespace,
		Name:        name,
		ConstLabels: additionalLabels,
	}, labelKeys)

	m.register(counter)
	return &incrementCounter{
		deregisterFunc: m.registry.Unregister,
		counter:        counter,
	}
}

func (m *metricsProvider) NewGauge(name string, additionalLabels map[string]string, labelKeys ...string) SetInstrument {
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace:   ebpfNamespace,
		Name:        name,
		ConstLabels: additionalLabels,
	}, labelKeys)

	m.register(gaugeVec)
	return &gauge{
		deregisterFunc: m.registry.Unregister,
		gauge:          gaugeVec,
	}
}

func (m *metricsProvider) register(collectors ...prometheus.Collector) {
	if m.registry != nil {
		m.registry.MustRegister(collectors...)
		return
	}
	prometheus.MustRegister(collectors...)
}

type setCounter struct {
	deregisterFunc func(prometheus.Collector) bool
	counter        *prometheus.CounterVec
	counterMap     map[uint64]int64
}

func (c *setCounter) Clean() {
	c.deregisterFunc(c.counter)
}

func (c *setCounter) Set(
	ctx context.Context,
	intVal int64,
	decodedKey map[string]string,
) {

	keyHash, err := hashstructure.Hash(decodedKey, hashstructure.FormatV2, nil)
	if err != nil {
		log.Fatal("This should never happen")
	}

	oldVal := c.counterMap[keyHash]
	diff := intVal - oldVal
	if oldVal == intVal {
		return
	}
	c.counterMap[keyHash] = intVal
	c.counter.With(prometheus.Labels(decodedKey)).Add(float64(diff))
}

type incrementCounter struct {
	deregisterFunc func(prometheus.Collector) bool
	counter        *prometheus.CounterVec
}

func (i *incrementCounter) Clean() {
	i.deregisterFunc(i.counter)
}

func (i *incrementCounter) Increment(
	ctx context.Context,
	decodedKey map[string]string,
) {
	i.counter.With(prometheus.Labels(decodedKey)).Inc()
}

type gauge struct {
	deregisterFunc func(prometheus.Collector) bool
	gauge          *prometheus.GaugeVec
}

func (g *gauge) Clean() {
	g.deregisterFunc(g.gauge)
}

func (g *gauge) Set(
	ctx context.Context,
	intVal int64,
	decodedKey map[string]string,
) {
	g.gauge.With(prometheus.Labels(decodedKey)).Set(float64(intVal))
}
