package loader

import (
	"log"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
	metric_sdk "go.opentelemetry.io/otel/sdk/export/metric"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	selector "go.opentelemetry.io/otel/sdk/metric/selector/simple"
)

const (
	ebpfMeter = "ebpf.solo.io"
)

var (
	lemonsKey = attribute.Key("ex.com/lemons")
)

func initMeter() {
	config := prometheus.Config{}
	// TODO: Figure out these options
	c := controller.New(
		processor.NewFactory(
			selector.NewWithExactDistribution(),
			metric_sdk.CumulativeExportKindSelector(),
			processor.WithMemory(true),
		),
	)
	exporter, err := prometheus.New(config, c)
	if err != nil {
		log.Panicf("failed to initialize prometheus exporter %v", err)
	}
	global.SetMeterProvider(exporter.MeterProvider())

	http.HandleFunc("/", exporter.ServeHTTP)
	go func() {
		_ = http.ListenAndServe(":2222", nil)
	}()

	// fmt.Println("Prometheus server running on :2222")
}

type metricsProvider struct {
	counter metric.Int64Counter
}

// func main() {

// 	meter := global.Meter(ebpfMeter)

// 	tcpCounter := metric.Must(meter).NewInt64Counter("tcp_retransmit")

// 	commonLabels := []attribute.KeyValue{lemonsKey.Int(10), attribute.String("A", "1"), attribute.String("B", "2"), attribute.String("C", "3")}

// 	meter.RecordBatch(ctx, commonLabels)

// 	observerLock := new(sync.RWMutex)
// 	observerValueToReport := new(float64)
// 	observerLabelsToReport := new([]attribute.KeyValue)

// 	histogram := metric.Must(meter).NewFloat64Histogram("ex.com.two")
// 	counter := metric.Must(meter).NewFloat64Counter("ex.com.three")

// 	commonLabels := []attribute.KeyValue{lemonsKey.Int(10), attribute.String("A", "1"), attribute.String("B", "2"), attribute.String("C", "3")}
// 	notSoCommonLabels := []attribute.KeyValue{lemonsKey.Int(13)}

// 	ctx := context.Background()

// 	(*observerLock).Lock()
// 	*observerValueToReport = 1.0
// 	*observerLabelsToReport = commonLabels
// 	(*observerLock).Unlock()
// 	meter.RecordBatch(
// 		ctx,
// 		commonLabels,
// 		histogram.Measurement(2.0),
// 		counter.Measurement(12.0),
// 	)

// 	time.Sleep(5 * time.Second)

// 	(*observerLock).Lock()
// 	*observerValueToReport = 1.0
// 	*observerLabelsToReport = notSoCommonLabels
// 	(*observerLock).Unlock()
// 	meter.RecordBatch(
// 		ctx,
// 		notSoCommonLabels,
// 		histogram.Measurement(2.0),
// 		counter.Measurement(22.0),
// 	)

// 	time.Sleep(5 * time.Second)

// 	(*observerLock).Lock()
// 	*observerValueToReport = 13.0
// 	*observerLabelsToReport = commonLabels
// 	(*observerLock).Unlock()
// 	meter.RecordBatch(
// 		ctx,
// 		commonLabels,
// 		histogram.Measurement(12.0),
// 		counter.Measurement(13.0),
// 	)

// 	fmt.Println("Example finished updating, please visit :2222")

// 	select {}
// }
