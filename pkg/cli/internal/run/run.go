package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/solo-io/gloobpf/pkg/loader"
	"github.com/solo-io/gloobpf/pkg/packaging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
)

type RunOptions struct {
	RawELF bool
}

func addToFlags(flags *pflag.FlagSet, opts *RunOptions) {
	flags.BoolVar(&opts.RawELF, "raw", false, "Run an eBPF program contained in a raw, standalone ELF binary file")
}

func RunCommand(opts *RunOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "run",
		Aliases: []string{"r"},
		Args:    cobra.ExactArgs(1), // Filename or image
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, opts)
		},
	}
	addToFlags(cmd.PersistentFlags(), opts)
	return cmd
}

func run(cmd *cobra.Command, args []string, opts *RunOptions) error {
	var progReader io.ReaderAt
	var err error
	if opts.RawELF {
		// just open file directly
		progReader, err = os.Open(args[0])
		if err != nil {
			return err
		}
	} else {
		progReader, err = getProgram(cmd, args)
		if err != nil {
			return err
		}
	}

	return runProg(cmd.Context(), progReader)
}

func getProgram(cmd *cobra.Command, args []string) (io.ReaderAt, error) {
	// guaranteed to be length 1
	progLocation := args[0]
	var progReader io.ReaderAt
	_, err := os.Stat(progLocation)
	if err != nil {
		reg, err := content.NewRegistry(content.RegistryOptions{
			Insecure:  true,
			PlainHTTP: true,
		})
		if err != nil {
			return nil, err
		}
		packager := packaging.NewEbpfRegistry(reg)

		prog, err := packager.Pull(cmd.Context(), progLocation)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(prog.ProgramFileBytes), nil
	} else {
		// Attempt to use file
		progReader, err = os.Open(progLocation)
		if err != nil {
			return nil, err
		}
	}

	return progReader, nil
}

func runProg(ctx context.Context, progReader io.ReaderAt) error {

	ctx, cancel := context.WithCancel(ctx)

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit: %v", err)
	}
	progOptions := &loader.LoadOptions{
		EbpfProg: progReader,
	}

	progLoader := loader.NewLoader(loader.NewDecoderFactory())
	return progLoader.Load(ctx, progOptions)
}
