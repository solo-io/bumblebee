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
	if err := loadBpfProgram(ctx, "bpf_bpfel.o"); err != nil {
		panic(fmt.Errorf("could not load bpf program %v", err))
	}

}

// struct event_t {
// 	u32 pid;
// 	u32 type;
// 	u64 addr;
// 	u64 skb_addr;
// 	u64 ts;
// } __attribute__((packed));

type Event struct {
	PID       uint32
	Type      uint32
	Addr      uint64
	SAddr     uint64
	Timestamp uint64
}

func loadBpfProgram(ctx context.Context, file string) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	fn, err := os.Open("out.btf")
	if err != nil {
		return err
	}
	defer fn.Close()

	typeSpec, err := btf.LoadRawSpec(fn, loader.Endianess)
	if err != nil {
		return err
	}

	var t *btf.Struct
	if err := typeSpec.FindType("event_t", &t); err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()

	kp, err := link.Kprobe(spec.Programs["kprobe_retransmit_skb"].AttachTo, coll.Programs["kprobe_retransmit_skb"])
	if err != nil {
		return err
	}
	defer kp.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(coll.Maps["events"])
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
		d := loader.NewDecoder(record.RawSample)
		result, err := d.TranslateRawBuffer(ctx, t)
		if err != nil {
			return err
		}

		fmt.Printf("%+v\n", result)

	}
}
