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
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/bumblebee/pkg/stats"
	"github.com/solo-io/bumblebee/pkg/tui"
	"github.com/solo-io/go-utils/contextutils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
)

type runOptions struct {
	general *options.GeneralOptions

	debug bool
}

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	runOptions := &runOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "run BPF_PROGRAM",
		Short: "Run a BPF program file or OCI image.",
		Long: `
The bee run command takes a compiled BPF program as input, and runs it using
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

	// guaranteed to be length 1
	progLocation := args[0]
	progReader, err := getProgram(cmd.Context(), opts.general, progLocation)
	if err != nil {
		return err
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit: %v", err)
	}
	promProvider, err := stats.NewPrometheusMetricsProvider(cmd.Context(), &stats.PrometheusOpts{})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)

	appOpts := tui.AppOpts{
		ProgLocation: progLocation,
	}
	app := tui.NewApp(progLoader, &appOpts)

	var sugaredLogger *zap.SugaredLogger
	if opts.debug {
		cfg := zap.NewDevelopmentConfig()
		cfg.OutputPaths = []string{"debug.log"}
		cfg.ErrorOutputPaths = []string{"debug.log"}
		logger, _ := cfg.Build()
		sugaredLogger = logger.Sugar()
	} else {
		sugaredLogger = zap.NewNop().Sugar()
	}

	ctx := contextutils.WithExistingLogger(cmd.Context(), sugaredLogger)
	return app.Run(ctx, progReader)
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
