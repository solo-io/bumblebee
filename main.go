package main

import (
	"bytes"
	"context"
	"encoding/binary"
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

		// // Parse the ringbuf event entry into an Event structure.
		// buf := bytes.NewBuffer(record.RawSample)
		// buf.Read()

		event := Event{}

		d := &decoder{raw: record.RawSample}

		d.translateRawBuffer(ctx, t)
		fmt.Printf("raw sample: %s\n", record.RawSample)
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%+v", event)
	}
}

type decoder struct {
	offset uint32
	raw    []byte
}

func (d *decoder) translateRawBuffer(
	ctx context.Context, typ *btf.Struct,
) error {
	// Parse the ringbuf event entry into an Event structure.
	// buf := bytes.NewBuffer(raw)
	for _, member := range typ.Members {
		_, err := d.processSingleType(member.Type)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) processSingleType(typ btf.Type) (interface{}, error) {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			// Default encoding seems to be unsigned
			fmt.Println(typedMember.Bits)
			fmt.Println(typedMember.Size)
			buf := bytes.NewBuffer(d.raw[d.offset : d.offset+typedMember.Size])
			d.offset += typedMember.Size
			switch typedMember.Bits {
			case 64:
				var val int64
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 32:
				var val int32
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 16:
				var val int16
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 8:
				var val int8
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			}
			return nil, errors.New("this should never happen")
		case btf.Bool:
			// TODO
			return false, nil
		case btf.Char:
			// TODO
			return "", nil
		default:
			// Default encoding seems to be unsigned
			buf := bytes.NewBuffer(d.raw[d.offset : d.offset+typedMember.Size])
			d.offset += typedMember.Size
			switch typedMember.Bits {
			case 64:
				var val uint64
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 32:
				var val uint32
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 16:
				var val uint16
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			case 8:
				var val uint8
				if err := binary.Read(buf, loader.Endianess, &val); err != nil {
					return nil, err
				}
				return val, nil
			}
			return nil, errors.New("this should never happen")
		}
	case *btf.Typedef:
		underlying, err := getUnderlyingType(typedMember)
		if err != nil {
			return nil, err
		}
		return d.processSingleType(underlying)
	case *btf.Float:
		return float64(0), nil
	default:
		return nil, errors.New("only primitive types allowed")
	}
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}
