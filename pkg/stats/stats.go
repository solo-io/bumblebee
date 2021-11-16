package stats

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	ebpfNamespace = "ebpf_solo_io"
)

type PrometheusOpts struct {
	Port        uint32
	MetricsPath string
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
	serveMux.Handle(opts.MetricsPath, promhttp.Handler())
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", opts.Port),
		Handler: serveMux,
	}
	go func() {
		_ = server.ListenAndServe()
	}()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return &metricsProvider{}, nil
}

type MetricsProvider interface {
	NewSetCounter(name string, labels []string) SetInstrument
	NewIncrementCounter(name string, labels []string) IncrementInstrument
	NewGauge(name string, labels []string) SetInstrument
}

type IncrementInstrument interface {
	Increment(ctx context.Context, labels map[string]string)
}

type SetInstrument interface {
	Set(ctx context.Context, val int64, labels map[string]string)
}

type metricsProvider struct{}

func (m *metricsProvider) NewSetCounter(name string, labels []string) SetInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)

	prometheus.MustRegister(counter)
	return &setCounter{
		counter:    counter,
		counterMap: map[uint64]int64{},
	}
}

func (m *metricsProvider) NewIncrementCounter(name string, labels []string) IncrementInstrument {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)

	prometheus.MustRegister(counter)
	return &incrementCounter{
		counter: counter,
	}
}

func (m *metricsProvider) NewGauge(name string, labels []string) SetInstrument {
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ebpfNamespace,
		Name:      name,
	}, labels)
	return &gauge{
		gauge: gaugeVec,
	}
}

type setCounter struct {
	counter    *prometheus.CounterVec
	counterMap map[uint64]int64
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
	counter *prometheus.CounterVec
}

func (i *incrementCounter) Increment(
	ctx context.Context,
	decodedKey map[string]string,
) {
	i.counter.With(prometheus.Labels(decodedKey)).Inc()
}

type gauge struct {
	gauge *prometheus.GaugeVec
}

func (g *gauge) Set(
	ctx context.Context,
	intVal int64,
	decodedKey map[string]string,
) {
	g.gauge.With(prometheus.Labels(decodedKey)).Set(float64(intVal))
}
