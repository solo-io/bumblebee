package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
	"golang.org/x/sync/errgroup"
)

type LoadOptions struct {
	EbpfProg io.ReaderAt
}

type Loader interface {
	Load(ctx context.Context, opts *LoadOptions) error
}

func NewLoader(decoderFactory DecoderFactory) Loader {
	initMeter()
	return &loader{
		decoderFactory: decoderFactory,
	}
}

type loader struct {
	decoderFactory DecoderFactory
}

func (l *loader) Load(ctx context.Context, opts *LoadOptions) error {

	// Generate the spec from out eBPF elf file
	spec, err := ebpf.LoadCollectionSpecFromReader(opts.EbpfProg)
	if err != nil {
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
		return err
	}
	defer coll.Close()

	// For each program, add kprope/tracepoint
	for name, prog := range spec.Programs {
		switch prog.Type {
		case ebpf.Kprobe:
			// Name of coll.Program should match
			kp, err := link.Kprobe(prog.AttachTo, coll.Programs[name])
			if err != nil {
				return err
			}
			defer kp.Close()
		default:
			return errors.New("only kprobe programs supported")
		}
	}

	eg, ctx := errgroup.WithContext(ctx)

	for name, bpfMap := range spec.Maps {
		name := name
		bpfMap := bpfMap
		switch bpfMap.Type {
		case ebpf.PerfEventArray:
			fallthrough
		case ebpf.RingBuf:
			eg.Go(func() error {
				return l.startRingBuf(ctx, btfMapMap, coll, name)
			})
		case ebpf.Hash:
			eg.Go(func() error {
				return l.startHashMap(ctx, bpfMap, coll.Maps[name], name)
			})
		case ebpf.Array:
			eg.Go(func() error {
				return l.startHashMap(ctx, bpfMap, coll.Maps[name], name)
			})
		default:
			// TODO: Support more map types
			return errors.New("only ringbuf, and perf event array supported")
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
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-ctx.Done()

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return nil
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		result, err := d.DecodeBtfBinary(ctx, t, record.RawSample)
		if err != nil {
			return err
		}

		// TODO: Handle statistic, or structured logging
		fmt.Printf("%+v\n", result)

	}
}

func (l *loader) startHashMap(
	ctx context.Context,
	mapSpec *ebpf.MapSpec,
	liveMap *ebpf.Map,
	name string,
) error {

	meter := global.Meter(ebpfMeter)
	tcpCounter := metric.Must(meter).NewInt64Counter("tcp_retransmit")
	commonLabels := []attribute.KeyValue{attribute.String("A", "1"), attribute.String("B", "2"), attribute.String("C", "3")}

	d := l.decoderFactory()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

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
					return err
				}
				decodedValue, err := d.DecodeBtfBinary(ctx, mapSpec.BTF.Value, value)
				if err != nil {
					return err
				}

				fmt.Printf("%s\n", decodedKey)
				fmt.Printf("%s\n", decodedValue)

				if len(decodedValue) > 1 {
					log.Fatal("only 1 value allowed")
				}

				intVal, ok := decodedValue[""].(uint64)
				if !ok {
					log.Fatal("only uint64 allowed")
				}

				meter.RecordBatch(ctx, commonLabels, tcpCounter.Measurement(int64(intVal)))
			}
		case <-ctx.Done():
			return nil
		}
	}
}
