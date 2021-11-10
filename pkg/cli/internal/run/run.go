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
	"github.com/solo-io/gloobpf/pkg/cli/internal/options"
	"github.com/solo-io/gloobpf/pkg/loader"
	"github.com/solo-io/gloobpf/pkg/packaging"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"oras.land/oras-go/pkg/content"
)

type runOptions struct {
	general *options.GeneralOptions
}

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {}

func Command(opts *options.GeneralOptions) *cobra.Command {
	runOptions := &runOptions{
		general: opts,
	}
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
			return run(cmd, args, runOptions)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), runOptions)
	return cmd
}

func run(cmd *cobra.Command, args []string, opts *runOptions) error {
	// gauranteed to be length 1
	progLocation := args[0]
	progReader, err := getProgram(cmd.Context(), opts.general, progLocation)
	if err != nil {
		return err
	}

	return runProg(cmd.Context(), progReader)
}

func getProgram(
	ctx context.Context,
	opts *options.GeneralOptions,
	progLocation string,
) (io.ReaderAt, error) {

	var (
		progReader     io.ReaderAt
		programSpinner *pterm.SpinnerPrinter
	)
	_, err := os.Stat(progLocation)
	if err != nil {
		programSpinner, _ = pterm.DefaultSpinner.Start(
			fmt.Sprintf("Fetching program from registry: %s", progLocation),
		)
		progBytes, err := fetchOciImage(ctx, opts, progLocation)
		if err != nil {
			programSpinner.UpdateText("Failed to load OCI image")
			programSpinner.Fail()
			return nil, err
		}
		progReader = bytes.NewReader(progBytes)
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

func fetchOciImage(
	ctx context.Context,
	opts *options.GeneralOptions,
	ref string,
) ([]byte, error) {

	packager := packaging.NewEbpfRegistry()

	if ociReg, err := content.NewOCI(opts.OCIStorageDir); err == nil {
		prog, err := packager.Pull(ctx, ref, ociReg)
		if err == nil {
			return prog.ProgramFileBytes, nil
		}
	}

	pterm.Info.Printfln("%s not found locally, pulling from registry", ref)

	reg, err := content.NewRegistry(content.RegistryOptions{
		Insecure:  true,
		PlainHTTP: true,
	})
	if err != nil {
		return nil, err
	}

	prog, err := packager.Pull(ctx, ref, reg)
	if err != nil {
		return nil, err
	}
	return prog.ProgramFileBytes, nil
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
