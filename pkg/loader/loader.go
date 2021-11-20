package loader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/pterm/pterm"
	"github.com/rivo/tview"
	"github.com/solo-io/ebpf/pkg/decoder"
	"github.com/solo-io/ebpf/pkg/internal/version"
	"github.com/solo-io/ebpf/pkg/printer"
	"github.com/solo-io/ebpf/pkg/stats"
	"golang.org/x/sync/errgroup"
)

type LoadOptions struct {
	// Program bytes to load
	EbpfProg io.ReaderAt
	// Log all events, this can be very loud
	Verbose bool
}

type Loader interface {
	Load(ctx context.Context, opts *LoadOptions) error
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

type loader struct {
	decoderFactory  decoder.DecoderFactory
	metricsProvider stats.MetricsProvider
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
		if mapSpec.Type == ebpf.RingBuf || mapSpec.Type == ebpf.PerfEventArray {
			btfMapMap[name] = mapSpec.BTF
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
		default:
			linkerProgress.Fail()
			return errors.New("only kprobe programs supported")
		}
	}
	linkerProgress.Success()

	eg, ctx := errgroup.WithContext(ctx)

	for name, bpfMap := range spec.Maps {
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
			// TODO: Support *btf.Union
			structType := btfMapMap[name].Value.(*btf.Struct)
			verbose := opts.Verbose
			if isCounterMap(bpfMap) {
				labelKeys := getLabelsForBtfStruct(structType)
				increment = l.metricsProvider.NewIncrementCounter(name, labelKeys)
			} else if isPrintMap(bpfMap) {
				increment = &noopIncrement{}
				verbose = true
			}
			eg.Go(func() error {
				pterm.Info.Printfln("Starting watch for ringbuf (%s)", name)
				return l.startRingBuf(ctx, structType, coll, increment, name, verbose)
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
				pterm.Info.Printfln("Starting watch for hashmap with counter (%s)", name)
				instrument = l.metricsProvider.NewSetCounter(bpfMap.Name, labelKeys)
			} else if isGaugeMap(bpfMap) {
				pterm.Info.Printfln("Starting watch for hashmap with gauge (%s)", name)
				instrument = l.metricsProvider.NewGauge(bpfMap.Name, labelKeys)
			}
			eg.Go(func() error {
				// return l.startHashMap(ctx, bpfMap, coll.Maps[name], instrument, name, opts.Verbose, flex, app)
				return l.startHashMap(ctx, bpfMap, coll.Maps[name], instrument, name, opts.Verbose)
			})
		default:
			// TODO: Support more map types
			return errors.New("unsupported map type")
		}
	}

	return eg.Wait()
}

func (l *loader) startRingBuf(
	ctx context.Context,
	valueStruct *btf.Struct,
	coll *ebpf.Collection,
	incrementInstrument stats.IncrementInstrument,
	name string,
	verbose bool,
) error {
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

		if err := rd.Close(); err != nil {
			pterm.Warning.Printf("closing ringbuf reader: %s", err)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			pterm.Warning.Printf("reading from reader: %s", err)
			continue
		}
		result, err := d.DecodeBtfBinary(ctx, valueStruct, record.RawSample)
		if err != nil {
			return err
		}

		stringLabels := stringify(result)
		incrementInstrument.Increment(ctx, stringLabels)
		if !verbose {
			continue
		}
		printMap := map[string]interface{}{
			"mapName": name,
			"entry":   stringLabels,
		}

		byt, err := json.Marshal(printMap)
		if err != nil {
			pterm.Debug.Printfln("error marshalling map data, this should never happen, %s", err)
			continue
		}
		fmt.Printf("%s\n", byt)

	}
}

func (l *loader) startHashMap(
	ctx context.Context,
	mapSpec *ebpf.MapSpec,
	liveMap *ebpf.Map,
	instrument stats.SetInstrument,
	name string,
	verbose bool,
	// flex *tview.Flex,
	// app *tview.Application,
) error {
	m := printer.NewMonitor()
	go m.Watch("test")
	table := tview.NewTable().SetFixed(1, 0)
	table.SetBorder(true).SetTitle(name)
	m.Flex.AddItem(table, 0, 1, false)

	d := l.decoderFactory()
	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:

			var entries []version.KvPair

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
					fmt.Println("error decoding key")
					return err
				}

				decodedValue, err := d.DecodeBtfBinary(ctx, mapSpec.BTF.Value, value)
				if err != nil {
					fmt.Println("error decoding value")
					return err
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
				thisKvPair := version.KvPair{Key: stringLabels, Value: fmt.Sprint(intVal)}
				entries = append(entries, thisKvPair)
			}

			if len(entries) == 0 || !verbose {
				continue
			}

			m.MyChan <- version.MapEntries{
				Name:    name,
				Entries: entries,
			}

			entry := entries[0]
			theekMap := entry.Key
			keyStructKeys := []string{}
			for kk := range theekMap {
				keyStructKeys = append(keyStructKeys, kk)
			}
			sort.Strings(keyStructKeys)

			table.ScrollToBeginning().Clear()
			c := 0
			for i, k := range keyStructKeys {
				cell := tview.NewTableCell(k).SetExpansion(1)
				// table.SetCellSimple(0, i, k)
				table.SetCell(0, i, cell)
				c++
			}
			cell := tview.NewTableCell("value").SetExpansion(1)
			table.SetCell(0, c, cell)
			for r, entry := range entries {
				r++
				ekMap := entry.Key
				eVal := entry.Value
				c := 0
				for kk, kv := range keyStructKeys {
					cell := tview.NewTableCell(ekMap[kv]).SetExpansion(1)
					table.SetCell(r, kk, cell)
					c++
				}
				cell := tview.NewTableCell(eVal).SetExpansion(1)
				table.SetCell(r, c, cell)
			}
			m.App.Draw()

			// textView.Clear()
			// fmt.Fprintf(textView, "%s\n", byt)

		case <-ctx.Done():
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
