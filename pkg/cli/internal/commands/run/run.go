package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
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

	debug  bool
	filter []string
}

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
	flags.StringSliceVarP(&opts.filter, "filter", "f", []string{}, "Filter to apply to output from maps, uses format: `map_name,key_name,regex`")
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
		return fmt.Errorf("could not raise memory limit (check for sudo or setcap): %v", err)
	}

	promProvider, err := stats.NewPrometheusMetricsProvider(cmd.Context(), &stats.PrometheusOpts{})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)

	parsedELF, err := progLoader.Parse(cmd.Context(), progReader)
	if err != nil {
		return fmt.Errorf("could not parse BPF program: %w", err)
	}

	// TODO: add filter to UI
	filter, err := buildFilter(opts.filter, parsedELF.WatchedMaps)
	if err != nil {
		return fmt.Errorf("could not build filter %w", err)
	}

	appOpts := tui.AppOpts{
		Loader:       progLoader,
		ProgLocation: progLocation,
		ParsedELF:    parsedELF,
		Filter:       filter,
	}
	app := tui.NewApp(&appOpts)

	var sugaredLogger *zap.SugaredLogger
	if opts.debug {
		cfg := zap.NewDevelopmentConfig()
		cfg.OutputPaths = []string{"debug.log"}
		cfg.ErrorOutputPaths = []string{"debug.log"}
		logger, err := cfg.Build()
		if err != nil {
			return fmt.Errorf("couldn't create zap logger: '%w'", err)
		}
		sugaredLogger = logger.Sugar()
	} else {
		sugaredLogger = zap.NewNop().Sugar()
	}

	ctx := contextutils.WithExistingLogger(cmd.Context(), sugaredLogger)
	return app.Run(ctx, progReader)
}

func buildFilter(filterString []string, watchedMaps map[string]loader.WatchedMap) (*tui.Filter, error) {
	if len(filterString) == 0 {
		return nil, nil
	}
	if len(filterString) != 3 {
		return nil, fmt.Errorf("filter syntax error, should have 3 fields, found %v", len(filterString))
	}

	mapName := filterString[0]
	labelName := filterString[1]

	if _, ok := watchedMaps[mapName]; !ok {
		return nil, fmt.Errorf("didnt find map '%v'", mapName)
	}
	var foundKeyName bool
	for _, v := range watchedMaps[mapName].Labels {
		if v == labelName {
			foundKeyName = true
		}
	}
	if !foundKeyName {
		return nil, fmt.Errorf("didnt find key val '%v'", labelName)
	}

	regex := regexp.MustCompile(filterString[2])
	filter := &tui.Filter{
		MapName:  mapName,
		KeyField: labelName,
		Regex:    regex,
	}
	return filter, nil
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
			if err, ok := err.(interface {
				StackTrace() errors.StackTrace
			}); ok {
				for _, f := range err.StackTrace() {
					fmt.Printf("%+s:%d\n", f, f)
				}
			}

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
