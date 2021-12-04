package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/pterm/pterm"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/stats"
	"golang.org/x/sync/errgroup"
)

type LoadOptions struct {
	// Program bytes to load
	EbpfProg io.ReaderAt
	// Log to debug.log file
	Debug   bool
	Watcher MapWatcher
}

type Loader interface {
	Load(ctx context.Context, opts *LoadOptions) error
}

type KvPair struct {
	Key   map[string]string
	Value string
	Hash  uint64
}

type MapEntry struct {
	Name  string
	Entry KvPair
}

type MapWatcher interface {
	NewRingBuf(name string, keys []string)
	NewHashMap(name string, keys []string)
	SendEntry(entry MapEntry)
	PreWatchHandler()
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
	counterMapType = "counter"
	gaugeMapType   = "gauge"
	printMapType   = "print"
)

func isPrintMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, printMapType)
}

func isGaugeMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, gaugeMapType)
}

func isCounterMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, counterMapType)
}

func isTrackedMap(spec *ebpf.MapSpec) bool {
	return isCounterMap(spec) || isGaugeMap(spec) || isPrintMap(spec)
}

func (l *loader) Load(ctx context.Context, opts *LoadOptions) error {

	loaderProgress, _ := pterm.DefaultSpinner.Start("Loading BPF program and maps into Kernel")

	// Generate the spec from out eBPF elf file
	spec, err := ebpf.LoadCollectionSpecFromReader(opts.EbpfProg)
	if err != nil {
		loaderProgress.Fail()
		return err
	}

	btfMapMap := make(map[string]*btf.Map)

	// TODO: Delete Hack if possible
	for name, mapSpec := range spec.Maps {
		if !isTrackedMap(mapSpec) {
			continue
		}
		if mapSpec.Type == ebpf.RingBuf || mapSpec.Type == ebpf.PerfEventArray {
			btfMap := mapSpec.BTF
			if _, ok := btfMap.Value.(*btf.Struct); !ok {
				return fmt.Errorf("the `value` member for map '%v' must be set to struct you will be submitting to the ringbuf/eventarray", name)
			}
			btfMapMap[name] = btfMap
			mapSpec.BTF = nil
			mapSpec.ValueSize = 0
		}
	}

	// Load our eBPF spec into the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		loaderProgress.Fail()
		return err
	}
	defer coll.Close()
	loaderProgress.Success()

	linkerProgress, _ := pterm.DefaultSpinner.Start("Linking BPF functions to associated probe/tracepoint")
	// For each program, add kprope/tracepoint
	for name, prog := range spec.Programs {
		switch prog.Type {
		case ebpf.Kprobe:
			var kp link.Link
			var err error
			if strings.HasPrefix(prog.SectionName, "kretprobe/") {
				kp, err = link.Kretprobe(prog.AttachTo, coll.Programs[name])
				if err != nil {
					linkerProgress.Fail()
					return fmt.Errorf("error attaching kretprobe '%v': %w", prog.Name, err)
				}
			} else {
				kp, err = link.Kprobe(prog.AttachTo, coll.Programs[name])
				if err != nil {
					linkerProgress.Fail()
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
				tp, err = link.Tracepoint(tokens[0], tokens[1], coll.Programs[name])
				if err != nil {
					linkerProgress.Fail()
					return fmt.Errorf("error attaching to tracepoint '%v': %w", prog.Name, err)
				}
			}
			defer tp.Close()
		default:
			linkerProgress.Fail()
			return errors.New("only kprobe programs supported")
		}
	}
	linkerProgress.Success()

	// TODO: break this functionality apart, need to handle deferred closes of all resources when solving
	return l.watchMaps(ctx, spec.Maps, btfMapMap, coll, opts)
}

func (l *loader) watchMaps(ctx context.Context, maps map[string]*ebpf.MapSpec, btfMapMap map[string]*btf.Map, coll *ebpf.Collection, opts *LoadOptions) error {
	opts.Watcher.PreWatchHandler()

	eg, ctx := errgroup.WithContext(ctx)
	for name, bpfMap := range maps {
		name := name
		bpfMap := bpfMap

		if !isTrackedMap(bpfMap) {
			continue
		}

		switch bpfMap.Type {
		case ebpf.PerfEventArray:
			fallthrough
		case ebpf.RingBuf:
			var increment stats.IncrementInstrument
			// this assertion checked when initially populating the `btfMapMap`
			structType := btfMapMap[name].Value.(*btf.Struct)
			labelKeys := getLabelsForBtfStruct(structType)
			if isCounterMap(bpfMap) {
				increment = l.metricsProvider.NewIncrementCounter(name, labelKeys)
			} else if isPrintMap(bpfMap) {
				increment = &noopIncrement{}
			}
			eg.Go(func() error {
				return l.startRingBuf(ctx, structType, coll, increment, name, labelKeys, opts)
			})
		case ebpf.Array:
			fallthrough
		case ebpf.Hash:
			labelKeys, err := getLabelsForHashMapKey(bpfMap)
			if err != nil {
				return err
			}
			var instrument stats.SetInstrument
			if isCounterMap(bpfMap) {
				instrument = l.metricsProvider.NewSetCounter(bpfMap.Name, labelKeys)
			} else if isGaugeMap(bpfMap) {
				instrument = l.metricsProvider.NewGauge(bpfMap.Name, labelKeys)
			}
			eg.Go(func() error {
				// TODO: output type of instrument in UI?
				return l.startHashMap(ctx, bpfMap, coll.Maps[name], instrument, name, labelKeys, opts)
			})
		default:
			// TODO: Support more map types
			return errors.New("unsupported map type")
		}
	}

	err := eg.Wait()
	log.Println("after waitgroup")
	return err
}

func (l *loader) startRingBuf(
	ctx context.Context,
	valueStruct *btf.Struct,
	coll *ebpf.Collection,
	incrementInstrument stats.IncrementInstrument,
	name string,
	keys []string,
	opts *LoadOptions,
) error {
	opts.Watcher.NewRingBuf(name, keys)
	// Initialize decoder
	d := l.decoderFactory()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(coll.Maps[name])
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()
	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-ctx.Done()
		log.Println("in ringbuf watcher, got done...")
		if err := rd.Close(); err != nil {
			log.Printf("error while closing ringbuf '%s' reader: %s", name, err)
		}
		log.Println("after reader.Close()")
	}()

	for {
		record, err := rd.Read()
		log.Println("read...")
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf closed...")
				return nil
			}
			log.Printf("error while reading from ringbuf '%s' reader: %s", name, err)
			continue
		}
		result, err := d.DecodeBtfBinary(ctx, valueStruct, record.RawSample)
		if err != nil {
			return err
		}

		stringLabels := stringify(result)
		incrementInstrument.Increment(ctx, stringLabels)
		opts.Watcher.SendEntry(MapEntry{
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
	keys []string,
	opts *LoadOptions,
) error {
	opts.Watcher.NewHashMap(name, keys)
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
				opts.Watcher.SendEntry(MapEntry{
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
	structKey, ok := mapSpec.BTF.Key.(*btf.Struct)
	if !ok {
		// TODO; move this check earlier
		return nil, fmt.Errorf("hash map keys can only be a struct, found %s", mapSpec.BTF.Value.String())
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

type noopIncrement struct{}

func (n *noopIncrement) Increment(
	ctx context.Context,
	decodedKey map[string]string,
) {
}
