package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
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

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.Debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
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
	// Subscribe to signals for terminating the program.
	// This is used until management of signals is passed to the TUI
	stopper = make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range stopper {
			if sig == os.Interrupt || sig == syscall.SIGTERM {
				fmt.Println("got sigterm or interrupt")
				os.Exit(0)
			}
		}
	}()

	if opts.Debug {
		f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	// defer cancel to whenever the TUI has been closed (via <ctrl-c>)
	m := printer.NewMonitor(cancel, opts.Debug)
	// guaranteed to be length 1
	progLocation := args[0]
	progReader, err := getProgram(ctx, opts.general, progLocation, m)
	if err != nil {
		return err
	}

	return runProg(ctx, progReader, opts.Debug, m)
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
		programSpinner, _ = pterm.DefaultSpinner.Start(
			fmt.Sprintf("Fetching program from registry: %s", progLocation),
		)
		m.SetFetchText(fmt.Sprintf("Fetching program from registry: [aqua]%s", progLocation))

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
			m.SetFetchText("Failed to load OCI image")
			return nil, err
		}
		progReader = bytes.NewReader(prog.ProgramFileBytes)
	} else {
		programSpinner, _ = pterm.DefaultSpinner.Start(
			fmt.Sprintf("Fetching program from file: %s", progLocation),
		)
		m.SetFetchText(fmt.Sprintf("Fetching program from file: %s", progLocation))
		// Attempt to use file
		progReader, err = os.Open(progLocation)
		if err != nil {
			programSpinner.UpdateText("Failed to open BPF file")
			programSpinner.Fail()
			m.SetFetchText("Failed to open BPF file")
			return nil, err
		}
	}
	programSpinner.Success()
	m.SetFetchText(fmt.Sprintf("Program location: [aqua]%s", progLocation))

	return progReader, nil
}

func runProg(ctx context.Context, progReader io.ReaderAt, debug bool, m printer.Monitor) error {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit: %v", err)
	}
	progOptions := &loader.LoadOptions{
		EbpfProg: progReader,
		Debug:    debug,
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
	// shut down the local signal notification as the TUI will be taking control of it
	// signal.Stop(stopper)
	// close(stopper)

	err = progLoader.Load(ctx, progOptions)
	return err

}
