package mapwatcher

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"

	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/loader/util"
	"github.com/solo-io/bumblebee/pkg/stats"
	"github.com/solo-io/go-utils/contextutils"
)

type WatchedMap struct {
	Name   string
	Labels []string

	BTF     *btf.Map
	MapType ebpf.MapType
	MapSpec *ebpf.MapSpec

	ValueStruct *btf.Struct
}

type Watcher interface {
	// WatchMaps watches the loaded maps and notifies the given receiver of events.
	WatchMaps(ctx context.Context, receiver MapEventReceiver) error
	// Maps returns the list of WatchedMaps
	Maps() map[string]WatchedMap
}

func New(
	watchedMaps map[string]WatchedMap,
	loadedMaps map[string]*ebpf.Map,
	decoderFactory decoder.DecoderFactory,
	provider stats.MetricsProvider,
) Watcher {
	return &watcher{
		watchedMaps:     watchedMaps,
		loadedMaps:      loadedMaps,
		decoderFactory:  decoderFactory,
		metricsProvider: provider,
	}
}

type watcher struct {
	// watchedMaps represent the maps we care to watch.
	watchedMaps map[string]WatchedMap
	// loadedMaps represent the maps currently loaded into the kernel.
	loadedMaps map[string]*ebpf.Map
	// decoderFactory provides a mechanism to decode various BTF types.
	decoderFactory decoder.DecoderFactory
	// metricsProvider provides Prometheus metrics.
	metricsProvider stats.MetricsProvider
}

func (w *watcher) WatchMaps(ctx context.Context, receiver MapEventReceiver) error {
	// on shutdown notify receiver we have no more entries to send.
	defer receiver.Close()
	contextutils.LoggerFrom(ctx).Info("enter watchMaps()")
	eg, ctx := errgroup.WithContext(ctx)
	for name, bpfMap := range w.watchedMaps {
		name := name
		bpfMap := bpfMap

		switch bpfMap.MapType {
		case ebpf.RingBuf:
			var increment stats.IncrementInstrument
			if util.IsCounterMap(bpfMap.MapSpec) {
				increment = w.metricsProvider.NewIncrementCounter(name, bpfMap.Labels)
			} else if util.IsPrintMap(bpfMap.MapSpec) {
				increment = &noop{}
			}
			eg.Go(func() error {
				receiver.NewRingBuf(name, bpfMap.Labels)
				return w.startRingBuf(ctx, bpfMap.ValueStruct, w.loadedMaps[name], increment, name, receiver)
			})
		case ebpf.Array:
			fallthrough
		case ebpf.Hash, ebpf.LRUHash:
			labelKeys := bpfMap.Labels
			var instrument stats.SetInstrument
			if util.IsCounterMap(bpfMap.MapSpec) {
				instrument = w.metricsProvider.NewSetCounter(bpfMap.Name, labelKeys)
			} else if util.IsGaugeMap(bpfMap.MapSpec) {
				instrument = w.metricsProvider.NewGauge(bpfMap.Name, labelKeys)
			} else {
				instrument = &noop{}
			}
			eg.Go(func() error {
				// TODO: output type of instrument in UI?
				receiver.NewHashMap(name, labelKeys)
				return w.startHashMap(ctx, bpfMap.MapSpec, w.loadedMaps[name], instrument, name, receiver)
			})
		default:
			// TODO: Support more map types
			return errors.New("unsupported map type")
		}
	}

	err := eg.Wait()
	contextutils.LoggerFrom(ctx).Info("after waitgroup")
	return err
}

func (w *watcher) Maps() map[string]WatchedMap {
	return w.watchedMaps
}

func (w *watcher) startRingBuf(
	ctx context.Context,
	valueStruct *btf.Struct,
	liveMap *ebpf.Map,
	incrementInstrument stats.IncrementInstrument,
	name string,
	watcher MapEventReceiver,
) error {
	// Initialize decoder
	d := w.decoderFactory()
	logger := contextutils.LoggerFrom(ctx)

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(liveMap)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()
	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-ctx.Done()
		logger.Info("in ringbuf watcher, got done...")
		if err := rd.Close(); err != nil {
			logger.Infof("error while closing ringbuf '%s' reader: %s", name, err)
		}
		logger.Info("after reader.Close()")
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info("ringbuf closed...")
				return nil
			}
			logger.Infof("error while reading from ringbuf '%s' reader: %s", name, err)
			continue
		}
		result, err := d.DecodeBtfBinary(ctx, valueStruct, record.RawSample)
		if err != nil {
			return err
		}

		stringLabels := stringify(result)
		incrementInstrument.Increment(ctx, stringLabels)
		watcher.SendEntry(MapEntry{
			Name: name,
			Entry: KvPair{
				Key: stringLabels,
			},
		})
	}
}

func (w *watcher) startHashMap(
	ctx context.Context,
	mapSpec *ebpf.MapSpec,
	liveMap *ebpf.Map,
	instrument stats.SetInstrument,
	name string,
	watcher MapEventReceiver,
) error {
	d := w.decoderFactory()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			mapIter := liveMap.Iterate()
			for {
				// Use generic key,value so we can decode ourselves
				var (
					key, value []byte
				)
				if !mapIter.Next(&key, &value) {
					break
				}
				if err := mapIter.Err(); err != nil {
					return err
				}
				decodedKey, err := d.DecodeBtfBinary(ctx, mapSpec.BTF.Key, key)
				if err != nil {
					return fmt.Errorf("error decoding key: %w", err)
				}

				decodedValue, err := d.DecodeBtfBinary(ctx, mapSpec.BTF.Value, value)
				if err != nil {
					return fmt.Errorf("error decoding value: %w", err)
				}

				// TODO: Check this information at load time
				if len(decodedValue) > 1 {
					log.Fatal("only 1 value allowed")
				}
				intVal, ok := decodedValue[""].(uint64)
				if !ok {
					log.Fatal("only uint64 allowed")
				}
				stringLabels := stringify(decodedKey)
				instrument.Set(ctx, int64(intVal), stringLabels)
				thisKvPair := KvPair{Key: stringLabels, Value: fmt.Sprint(intVal)}
				watcher.SendEntry(MapEntry{
					Name:  name,
					Entry: thisKvPair,
				})
			}

		case <-ctx.Done():
			// fmt.Println("got done in hashmap loop, returning")
			return nil
		}
	}
}

func stringify(decodedBinary map[string]interface{}) map[string]string {
	keyMap := map[string]string{}
	for k, v := range decodedBinary {
		valAsStr := fmt.Sprint(v)
		keyMap[k] = valAsStr
	}
	return keyMap
}

type noop struct{}

func (n *noop) Increment(_ context.Context, _ map[string]string) {}

func (n *noop) Set(_ context.Context, _ int64, _ map[string]string) {}
