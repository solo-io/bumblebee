package loader

import (
	"context"
	"encoding/json"
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
	"golang.org/x/sync/errgroup"
)

type LoadOptions struct {
	EbpfProg io.ReaderAt
}

type Loader interface {
	Load(ctx context.Context, opts *LoadOptions) error
}

func NewLoader(
	decoderFactory DecoderFactory,
	metricsProvider MetricsProvider,
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

type loader struct {
	decoderFactory  DecoderFactory
	metricsProvider MetricsProvider
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
		switch bpfMap.Type {
		case ebpf.PerfEventArray:
			fallthrough
		case ebpf.RingBuf:
			if !isPrintMap(bpfMap) {
				continue
			}
			eg.Go(func() error {
				pterm.Info.Printfln("Starting watch for ringbuf (%s)", name)
				return l.startRingBuf(ctx, btfMapMap, coll, name)
			})
		case ebpf.Array:
			fallthrough
		case ebpf.Hash:
			var instrument Instrument
			if isCounterMap(bpfMap) {
				pterm.Info.Printfln("Starting watch for hashmap with counter (%s)", name)
				instrument = l.metricsProvider.NewCounter(bpfMap.Name)
			} else if isGaugeMap(bpfMap) {
				pterm.Info.Printfln("Starting watch for hashmap with gauge (%s)", name)
				instrument = l.metricsProvider.NewGauge(bpfMap.Name)
			}
			eg.Go(func() error {
				return l.startHashMap(ctx, bpfMap, coll.Maps[name], instrument, name)
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
	btfMapMap map[string]*btf.Map,
	coll *ebpf.Collection,
	name string,
) error {
	// Initialize decoder
	d := l.decoderFactory()

	// TODO: Support *btf.Union
	t := btfMapMap[name].Value.(*btf.Struct)

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
		result, err := d.DecodeBtfBinary(ctx, t, record.RawSample)
		if err != nil {
			return err
		}

		// TODO: Handle statistic, or structured logging
		byt, err := json.Marshal(result)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", name, byt)

	}
}

func (l *loader) startHashMap(
	ctx context.Context,
	mapSpec *ebpf.MapSpec,
	liveMap *ebpf.Map,
	instrument Instrument,
	name string,
) error {
	d := l.decoderFactory()
	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			// var all_cpu_value []uint64
			mapIter := liveMap.Iterate()
			for {
				// Use generic key,value so we can decode ourselves
				var (
					key, value []byte
				)
				// log.Println("Checking Iterator..")
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

				instrument.Set(ctx, int64(intVal), decodedKey)
			}
		case <-ctx.Done():
			return nil
		}
	}
}
