package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"

	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/stats"
	"github.com/solo-io/go-utils/contextutils"
)

type ParsedELF struct {
	Spec        *ebpf.CollectionSpec
	WatchedMaps map[string]WatchedMap
}

type LoadOptions struct {
	ParsedELF *ParsedELF
	Watcher   MapWatcher
	PinMaps   string
	PinProgs  string
}

type Loader interface {
	Parse(ctx context.Context, reader io.ReaderAt) (*ParsedELF, error)
	Load(ctx context.Context, opts *LoadOptions) error
	WatchMaps(ctx context.Context, watchedMaps map[string]WatchedMap, coll map[string]*ebpf.Map, watcher MapWatcher) error
}

type WatchedMap struct {
	Name   string
	Labels []string

	mapType ebpf.MapType
	mapSpec *ebpf.MapSpec

	valueStruct *btf.Struct
}

type loader struct {
	decoderFactory  decoder.DecoderFactory
	metricsProvider stats.MetricsProvider
}

func NewLoader(
	decoderFactory decoder.DecoderFactory,
	metricsProvider stats.MetricsProvider,
) Loader {
	return &loader{
		decoderFactory:  decoderFactory,
		metricsProvider: metricsProvider,
	}
}

const (
	counterMapPrefix = "counter_"
	gaugeMapPrefix   = "gauge_"
	printMapPrefix   = "print_"
)

func isPrintMap(spec *ebpf.MapSpec) bool {
	return strings.HasPrefix(spec.Name, printMapPrefix)
}

func isGaugeMap(spec *ebpf.MapSpec) bool {
	return strings.HasPrefix(spec.Name, gaugeMapPrefix)
}

func isCounterMap(spec *ebpf.MapSpec) bool {
	return strings.HasPrefix(spec.Name, counterMapPrefix)
}

func isTrackedMap(spec *ebpf.MapSpec) bool {
	return isCounterMap(spec) || isGaugeMap(spec) || isPrintMap(spec)
}

func (l *loader) Parse(ctx context.Context, progReader io.ReaderAt) (*ParsedELF, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, err
	}

	for _, prog := range spec.Programs {
		if prog.Type == ebpf.UnspecifiedProgram {
			contextutils.LoggerFrom(ctx).Debug("Program %s does not specify a type", prog.Name)
		}
	}

	watchedMaps := make(map[string]WatchedMap)
	for name, mapSpec := range spec.Maps {
		if !isTrackedMap(mapSpec) {
			continue
		}

		watchedMap := WatchedMap{
			Name:    name,
			mapType: mapSpec.Type,
			mapSpec: mapSpec,
		}

		// TODO: Delete Hack if possible
		if watchedMap.mapType == ebpf.RingBuf || watchedMap.mapType == ebpf.PerfEventArray {
			if _, ok := mapSpec.Value.(*btf.Struct); !ok {
				return nil, fmt.Errorf("the `value` member for map '%v' must be set to struct you will be submitting to the ringbuf/eventarray", name)
			}
			mapSpec.ValueSize = 0
		}

		switch mapSpec.Type {
		case ebpf.RingBuf:
			structType := mapSpec.Value.(*btf.Struct)
			watchedMap.valueStruct = structType
			labelKeys := getLabelsForBtfStruct(structType)

			watchedMap.Labels = labelKeys
		case ebpf.Hash:
			labelKeys, err := getLabelsForHashMapKey(mapSpec)
			if err != nil {
				return nil, err
			}

			watchedMap.Labels = labelKeys
		default:
			return nil, errors.New("unsupported map type")
		}

		watchedMaps[name] = watchedMap
	}

	loadOptions := ParsedELF{
		Spec:        spec,
		WatchedMaps: watchedMaps,
	}
	return &loadOptions, nil
}

func (l *loader) Load(ctx context.Context, opts *LoadOptions) error {
	// TODO: add invariant checks on opts
	contextutils.LoggerFrom(ctx).Info("enter Load()")
	// on shutdown notify watcher we have no more entries to send
	defer opts.Watcher.Close()

	// bail out before loading stuff into kernel if context canceled
	if ctx.Err() != nil {
		contextutils.LoggerFrom(ctx).Info("load entrypoint context is done")
		return ctx.Err()
	}

	if opts.PinMaps != "" {
		// Specify that we'd like to pin the referenced maps, or open them if already existing.
		for _, m := range opts.ParsedELF.Spec.Maps {
			// Do not pin/load read-only data
			if strings.HasSuffix(m.Name, ".rodata") {
				continue
			}

			// PinByName specifies that we should pin the map by name, or load it if it already exists.
			m.Pinning = ebpf.PinByName
		}
	}

	spec := opts.ParsedELF.Spec
	// Load our eBPF spec into the kernel
	coll, err := ebpf.NewCollectionWithOptions(opts.ParsedELF.Spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: opts.PinMaps,
		},
	})
	if err != nil {
		return err
	}
	defer coll.Close()

	// For each program, add kprope/tracepoint
	for name, prog := range spec.Programs {
		select {
		case <-ctx.Done():
			contextutils.LoggerFrom(ctx).Info("while loading progs context is done")
			return ctx.Err()
		default:
			switch prog.Type {
			case ebpf.Kprobe:
				var kp link.Link
				var err error
				if strings.HasPrefix(prog.SectionName, "kretprobe/") {
					kp, err = link.Kretprobe(prog.AttachTo, coll.Programs[name], nil)
					if err != nil {
						return fmt.Errorf("error attaching kretprobe '%v': %w", prog.Name, err)
					}
				} else {
					kp, err = link.Kprobe(prog.AttachTo, coll.Programs[name], nil)
					if err != nil {
						return fmt.Errorf("error attaching kprobe '%v': %w", prog.Name, err)
					}
				}
				defer kp.Close()
			case ebpf.TracePoint:
				var tp link.Link
				var err error
				if strings.HasPrefix(prog.SectionName, "tracepoint/") {
					tokens := strings.Split(prog.AttachTo, "/")
					if len(tokens) != 2 {
						return fmt.Errorf("unexpected tracepoint section '%v'", prog.AttachTo)
					}
					tp, err = link.Tracepoint(tokens[0], tokens[1], coll.Programs[name], nil)
					if err != nil {
						return fmt.Errorf("error attaching to tracepoint '%v': %w", prog.Name, err)
					}
				}
				defer tp.Close()
			default:
				return errors.New("only kprobe programs supported")
			}
			if opts.PinProgs != "" {
				if err := createDir(ctx, opts.PinProgs, 0700); err != nil {
					return err
				}

				pinFile := filepath.Join(opts.PinProgs, prog.Name)
				if err := coll.Programs[name].Pin(pinFile); err != nil {
					return fmt.Errorf("could not pin program '%s': %v", prog.Name, err)
				}
				fmt.Printf("Successfully pinned program '%v'\n", pinFile)
			}
		}
	}

	return l.WatchMaps(ctx, opts.ParsedELF.WatchedMaps, coll.Maps, opts.Watcher)
}

func (l *loader) WatchMaps(
	ctx context.Context,
	watchedMaps map[string]WatchedMap,
	maps map[string]*ebpf.Map,
	watcher MapWatcher,
) error {
	contextutils.LoggerFrom(ctx).Info("enter watchMaps()")
	eg, ctx := errgroup.WithContext(ctx)
	for name, bpfMap := range watchedMaps {
		name := name
		bpfMap := bpfMap

		switch bpfMap.mapType {
		case ebpf.RingBuf:
			var increment stats.IncrementInstrument
			if isCounterMap(bpfMap.mapSpec) {
				increment = l.metricsProvider.NewIncrementCounter(name, bpfMap.Labels)
			} else if isPrintMap(bpfMap.mapSpec) {
				increment = &noop{}
			}
			eg.Go(func() error {
				watcher.NewRingBuf(name, bpfMap.Labels)
				return l.startRingBuf(ctx, bpfMap.valueStruct, maps[name], increment, name, watcher)
			})
		case ebpf.Array:
			fallthrough
		case ebpf.Hash:
			labelKeys := bpfMap.Labels
			var instrument stats.SetInstrument
			if isCounterMap(bpfMap.mapSpec) {
				instrument = l.metricsProvider.NewSetCounter(bpfMap.Name, labelKeys)
			} else if isGaugeMap(bpfMap.mapSpec) {
				instrument = l.metricsProvider.NewGauge(bpfMap.Name, labelKeys)
			} else {
				instrument = &noop{}
			}
			eg.Go(func() error {
				// TODO: output type of instrument in UI?
				watcher.NewHashMap(name, labelKeys)
				return l.startHashMap(ctx, bpfMap.mapSpec, maps[name], instrument, name, watcher)
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

func (l *loader) startRingBuf(
	ctx context.Context,
	valueStruct *btf.Struct,
	liveMap *ebpf.Map,
	incrementInstrument stats.IncrementInstrument,
	name string,
	watcher MapWatcher,
) error {
	// Initialize decoder
	d := l.decoderFactory()
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

func (l *loader) startHashMap(
	ctx context.Context,
	mapSpec *ebpf.MapSpec,
	liveMap *ebpf.Map,
	instrument stats.SetInstrument,
	name string,
	watcher MapWatcher,
) error {
	d := l.decoderFactory()

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
				decodedKey, err := d.DecodeBtfBinary(ctx, mapSpec.Key, key)
				if err != nil {
					return fmt.Errorf("error decoding key: %w", err)
				}

				decodedValue, err := d.DecodeBtfBinary(ctx, mapSpec.Value, value)
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

func getLabelsForHashMapKey(mapSpec *ebpf.MapSpec) ([]string, error) {
	structKey, ok := mapSpec.Key.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("hash map keys can only be a struct, found %s", mapSpec.Value.TypeName())
	}

	return getLabelsForBtfStruct(structKey), nil
}

func getLabelsForBtfStruct(structKey *btf.Struct) []string {
	keys := make([]string, 0, len(structKey.Members))
	for _, v := range structKey.Members {
		keys = append(keys, v.Name)
	}
	return keys
}

type noop struct{}

func (n *noop) Increment(
	ctx context.Context,
	decodedKey map[string]string,
) {
}

func (n *noop) Set(
	ctx context.Context,
	val int64,
	labels map[string]string,
) {
}

func createDir(ctx context.Context, path string, perm os.FileMode) error {
	file, err := os.Stat(path)
	if os.IsNotExist(err) {
		contextutils.LoggerFrom(ctx).Info("path does not exist, creating pin directory: %s", path)
		return os.Mkdir(path, perm)
	} else if err != nil {
		return fmt.Errorf("could not create pin directory '%v': %w", path, err)
	} else if !file.IsDir() {
		return fmt.Errorf("pin location '%v' exists but is not a directory", path)
	}

	return nil
}
