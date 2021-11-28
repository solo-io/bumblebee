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
	"github.com/solo-io/ebpf/pkg/cli/internal/options"
	"github.com/solo-io/ebpf/pkg/decoder"
	"github.com/solo-io/ebpf/pkg/loader"
	"github.com/solo-io/ebpf/pkg/printer"
	"github.com/solo-io/ebpf/pkg/spec"
	"github.com/solo-io/ebpf/pkg/stats"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type runOptions struct {
	general *options.GeneralOptions

	Debug bool
}

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.Debug, "debug", "d", false, "Output all user space map reads to the console for debugging purposes")
}

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
	ctx, cancel := context.WithCancel(cmd.Context())
	m := printer.NewMonitor(cancel)
	m.Start()
	// gauranteed to be length 1
	progLocation := args[0]
	progReader, err := getProgram(ctx, opts.general, progLocation, m)
	if err != nil {
		return err
	}

	return runProg(ctx, cancel, progReader, opts.Debug, m)
}

func getProgram(
	ctx context.Context,
	opts *options.GeneralOptions,
	progLocation string,
	m printer.Monitor,
) (io.ReaderAt, error) {

	var (
		progReader     io.ReaderAt
		programSpinner *pterm.SpinnerPrinter
	)
	_, err := os.Stat(progLocation)
	if err != nil {
		m.SetFetchText(fmt.Sprintf("Fetching program from registry: %s", progLocation))

		client := spec.NewEbpfOCICLient()
		prog, err := spec.TryFromLocal(
			ctx,
			progLocation,
			opts.OCIStorageDir,
			client,
			opts.AuthOptions.ToRegistryOptions(),
		)
		if err != nil {
			programSpinner.UpdateText("Failed to load OCI image")
			programSpinner.Fail()
			return nil, err
		}
		progReader = bytes.NewReader(prog.ProgramFileBytes)
	} else {
		m.SetFetchText(fmt.Sprintf("Fetching program from file: %s", progLocation))
		// Attempt to use file
		progReader, err = os.Open(progLocation)
		if err != nil {
			programSpinner.UpdateText("Failed to open BPF file")
			programSpinner.Fail()
			return nil, err
		}
	}
	//TODO: handle both program/registry text here...
	m.SetFetchText(fmt.Sprintf("success Fetching program from file: %s", progLocation))

	return progReader, nil
}

func runProg(ctx context.Context, cancel context.CancelFunc, progReader io.ReaderAt, debug bool, m printer.Monitor) error {

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		fmt.Println("got sigterm or interrupt")
	}()
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit: %v", err)
	}
	progOptions := &loader.LoadOptions{
		EbpfProg: progReader,
		Verbose:  debug,
	}

	promProvider, err := stats.NewPrometheusMetricsProvider(ctx, &stats.PrometheusOpts{})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
		m,
	)
	err = progLoader.Load(ctx, progOptions)
	close(m.MyChan)
	return err

}
