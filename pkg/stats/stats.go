package stats

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/solo-io/go-utils/contextutils"
)

const (
	ebpfNamespace = "ebpf_solo_io"
)

type PrometheusOpts struct {
	Port        uint32
	MetricsPath string
	Registry    *prometheus.Registry
}

func (p *PrometheusOpts) initDefaults() {
	if p.Port == 0 {
		p.Port = 9091
	}
	if p.MetricsPath == "" {
		p.MetricsPath = "/metrics"
	}
}

func NewPrometheusMetricsProvider(ctx context.Context, opts *PrometheusOpts) (MetricsProvider, error) {
	opts.initDefaults()

	serveMux := http.NewServeMux()
	handler := promhttp.Handler()
	if opts.Registry != nil {
		handler = promhttp.InstrumentMetricHandler(opts.Registry, promhttp.HandlerFor(opts.Registry, promhttp.HandlerOpts{}))
	}
	serveMux.Handle(opts.MetricsPath, handler)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", opts.Port),
		Handler: serveMux,
	}
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			contextutils.LoggerFrom(ctx).Errorf("could not listen for Prometheus metrics: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return &metricsProvider{
		registry: opts.Registry,
	}, nil
}

type MetricsProvider interface {
	NewSetCounter(name string, labels []string) SetInstrument
	NewIncrementCounter(name string, labels []string) IncrementInstrument
	NewGauge(name string, labels []string) SetInstrument
	NewHistogram(name string, labels []string, buckets []float64) SetInstrument
}

type IncrementInstrument interface {
	Increment(ctx context.Context, labels map[string]string)
	Clean(newLabels []map[string]string)
}

type SetInstrument interface {
	Set(ctx context.Context, val int64, labels map[string]string)
	Clean(newLabels []map[string]string)
}

type metricsProvider struct {
	registry *prometheus.Registry
}

func (m *metricsProvider) NewSetCounter(name string, labels []string) SetInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)

	m.register(counter)
	return &setCounter{
		counter:       counter,
		counterMap:    map[uint64]int64{},
		currentLabels: map[string]map[string]string{},
	}
}

func (m *metricsProvider) NewIncrementCounter(name string, labels []string) IncrementInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)

	m.register(counter)
	return &incrementCounter{
		counter:       counter,
		currentLabels: map[string]map[string]string{},
	}
}

func (m *metricsProvider) NewGauge(name string, labels []string) SetInstrument {
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)

	m.register(gaugeVec)
	return &gauge{
		gauge:         gaugeVec,
		currentLabels: map[string]map[string]string{},
	}
}

func (m *metricsProvider) NewHistogram(name string, labels []string, buckets []float64) SetInstrument {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ebpfNamespace,
		Name:      name,
		Buckets:   buckets,
	}, labels)

	m.register(h)
	return &histogram{
		histogram: h,
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
	counter       *prometheus.CounterVec
	counterMap    map[uint64]int64
	currentLabels map[string]map[string]string
}

func makeLabelString(label map[string]string) string {
	pairs := make([]string, 0, len(label))
	for k, v := range label {
		pairs = append(pairs, fmt.Sprintf("%s|%s", k, v))
	}
	return strings.Join(pairs, ",")
}

func (c *setCounter) trackLabel(decodedKey map[string]string) {
	c.currentLabels[makeLabelString(decodedKey)] = decodedKey
}

func (c *setCounter) Clean(newLabels []map[string]string) {
	labelsToKeep := make(map[string]bool)
	for _, newLabel := range newLabels {
		labelsToKeep[makeLabelString(newLabel)] = true
	}

	for oldLabelKey, oldLabel := range c.currentLabels {
		if _, ok := labelsToKeep[oldLabelKey]; !ok {
			delete(c.currentLabels, oldLabelKey)
			c.counter.Delete(oldLabel)
		}
	}
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
	c.trackLabel(decodedKey)
}

type incrementCounter struct {
	counter       *prometheus.CounterVec
	currentLabels map[string]map[string]string
}

func (i *incrementCounter) Increment(
	ctx context.Context,
	decodedKey map[string]string,
) {
	i.counter.With(prometheus.Labels(decodedKey)).Inc()
	i.trackLabel(decodedKey)
}

func (i *incrementCounter) trackLabel(decodedKey map[string]string) {
	i.currentLabels[makeLabelString(decodedKey)] = decodedKey
}

func (i *incrementCounter) Clean(newLabels []map[string]string) {
	labelsToKeep := make(map[string]bool)
	for _, newLabel := range newLabels {
		labelsToKeep[makeLabelString(newLabel)] = true
	}

	for oldLabelKey, oldLabel := range i.currentLabels {
		if _, ok := labelsToKeep[oldLabelKey]; !ok {
			delete(i.currentLabels, oldLabelKey)
			i.counter.Delete(oldLabel)
		}
	}
}

type gauge struct {
	gauge         *prometheus.GaugeVec
	currentLabels map[string]map[string]string
}

func (g *gauge) Set(
	ctx context.Context,
	intVal int64,
	decodedKey map[string]string,
) {
	g.gauge.With(prometheus.Labels(decodedKey)).Set(float64(intVal))
	g.trackLabel(decodedKey)
}

func (g *gauge) trackLabel(decodedKey map[string]string) {
	g.currentLabels[makeLabelString(decodedKey)] = decodedKey
}

func (g *gauge) Clean(newLabels []map[string]string) {
	labelsToKeep := make(map[string]bool)
	for _, newLabel := range newLabels {
		labelsToKeep[makeLabelString(newLabel)] = true
	}

	for oldLabelKey, oldLabel := range g.currentLabels {
		if _, ok := labelsToKeep[oldLabelKey]; !ok {
			delete(g.currentLabels, oldLabelKey)
			g.gauge.Delete(oldLabel)
		}
	}
}

type histogram struct {
	histogram *prometheus.HistogramVec
}

func (h *histogram) Set(
	ctx context.Context,
	intVal int64,
	decodedKey map[string]string,
) {
	h.histogram.With(prometheus.Labels(decodedKey)).Observe(float64(intVal))
}
