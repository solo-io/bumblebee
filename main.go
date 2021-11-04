package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/solo-io/ebpf-ext/pkg/loader"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()
	opts := &loadOptions{
		EbpfFile: "bpf_bpfel.o",
		BTFfile:  "out.btf",
	}
	if err := loadBpfPrograms(ctx, opts); err != nil {
		panic(fmt.Errorf("could not load bpf program %v", err))
	}

}

type loadOptions struct {
	EbpfFile string
	BTFfile  string
}

func loadBpfPrograms(ctx context.Context, opts *loadOptions) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Generate the spec from out eBPF elf file
	spec, err := ebpf.LoadCollectionSpec(opts.EbpfFile)
	if err != nil {
		return err
	}

	// Open the BTF definition file
	fn, err := os.Open(opts.BTFfile)
	if err != nil {
		return err
	}
	defer fn.Close()

	// Load the btf spec from out BTF definition file
	typeSpec, err := btf.LoadRawSpec(fn, loader.Endianess)
	if err != nil {
		return err
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

	for name, bpfMap := range spec.Maps {
		switch bpfMap.Type {
		case ebpf.PerfEventArray:
			fallthrough
		case ebpf.RingBuf:
			var t *btf.Struct
			if err := typeSpec.FindType("event_t", &t); err != nil {
				return err
			}

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
				d := loader.NewDecoder()
				result, err := d.DecodeBinaryStruct(ctx, t, record.RawSample)
				if err != nil {
					return err
				}

				fmt.Printf("%+v\n", result)

			}
		default:
			return errors.New("Only ringbuf, and perf event array supported")
		}
	}

	return nil
}
