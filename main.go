package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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
	bpfElfPath := os.Args[1]
	fmt.Printf("loading bpf ELF: '%v'\n", bpfElfPath)
	opts := &loader.LoadOptions{
		EbpfFile: bpfElfPath,
	}
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("could not raise memory limit: %v", err)
	}

	progLoader := loader.NewLoader(loader.NewDecoderFactory())
	if err := progLoader.Load(ctx, opts); err != nil {
		log.Fatalf("could not load bpf program %v", err)
	}
}
