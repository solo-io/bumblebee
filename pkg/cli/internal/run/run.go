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
	"github.com/pterm/pterm"
	"github.com/solo-io/gloobpf/pkg/loader"
	"github.com/solo-io/gloobpf/pkg/packaging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
)

type RunOptions struct{}

func addToFlags(flags *pflag.FlagSet, opts *RunOptions) {}

func RunCommand(opts *RunOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run BPF_PROGRAM",
		Short: "Run a BPF program file or OCI image.",
		Long: `
The ebpfctl run command takes a compiled BPF program as input, and runs it using
our generic loader. The supported formats are: file, and OCI image

To run with a file pass it as the first ARG:
$ run bpf-program.o

To run with a OCI image pass it as the first ARG:
$ run localhost:5000/oras:ringbuf-demo
`,
		Args: cobra.ExactArgs(1), // Filename or image
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, opts)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), opts)
	return cmd
}

func run(cmd *cobra.Command, args []string, opts *RunOptions) error {
	// gauranteed to be length 1
	progLocation := args[0]
	progReader, err := getProgram(cmd, progLocation)
	if err != nil {
		return err
	}

	return runProg(cmd.Context(), progReader)
}

func getProgram(cmd *cobra.Command, progLocation string) (io.ReaderAt, error) {

	var (
		progReader     io.ReaderAt
		programSpinner *pterm.SpinnerPrinter
	)
	_, err := os.Stat(progLocation)
	if err != nil {
		programSpinner, _ = pterm.DefaultSpinner.Start(
			fmt.Sprintf("Fetching program from registry: %s", progLocation),
		)
		reg, err := content.NewRegistry(content.RegistryOptions{
			Insecure:  true,
			PlainHTTP: true,
		})
		if err != nil {
			programSpinner.UpdateText("Failed to initialize registry")
			programSpinner.Fail()
			return nil, err
		}
		packager := packaging.NewEbpfRegistry(reg)

		prog, err := packager.Pull(cmd.Context(), progLocation)
		if err != nil {
			return nil, err
		}
		progReader = bytes.NewReader(prog.ProgramFileBytes)
	} else {
		programSpinner, _ = pterm.DefaultSpinner.Start(
			fmt.Sprintf("Fetching program from file: %s", progLocation),
		)
		// Attempt to use file
		progReader, err = os.Open(progLocation)
		if err != nil {
			programSpinner.UpdateText("Failed to open BPF file")
			programSpinner.Fail()
			return nil, err
		}
	}
	programSpinner.Success()

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
