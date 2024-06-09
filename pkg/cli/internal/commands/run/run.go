package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

	debug        bool
	filter       []string
	histBuckets  []string
	histValueKey []string
	notty        bool
	pinMaps      string
	pinProgs     string
	promPort     uint32
}

const histBucketsDescription string = "Buckets to use for histogram maps. Format is \"map_name,<buckets_limits>\"" +
	"where <buckets_limits> is a comma separated list of bucket limits. For example: \"events,[1,2,3,4,5]\""

const filterDescription string = "Filter to apply to output from maps. Format is \"map_name,key_name,regex\" " +
	"You can define a filter per map, if more than one defined, the last defined filter will take precedence"

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
	flags.StringSliceVarP(&opts.filter, "filter", "f", []string{}, filterDescription)
	flags.StringArrayVarP(&opts.histBuckets, "hist-buckets", "b", []string{}, histBucketsDescription)
	flags.StringArrayVarP(&opts.histValueKey, "hist-value-key", "k", []string{}, "Key to use for histogram maps. Format is \"map_name,key_name\"")
	flags.BoolVar(&opts.notty, "no-tty", false, "Set to true for running without a tty allocated, so no interaction will be expected or rich output will done")
	flags.StringVar(&opts.pinMaps, "pin-maps", "", "Directory to pin maps to, left unpinned if empty")
	flags.StringVar(&opts.pinProgs, "pin-progs", "", "Directory to pin progs to, left unpinned if empty")
	flags.Uint32Var(&opts.promPort, "prom-port", 9091, "Specify the Prometheus listener port")
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
$ bee run bpf-program.o

To run with a OCI image pass it as the first ARG:
$ bee run localhost:5000/oras:ringbuf-demo

To run with a filter on the output in the TUI, use the --filter (or -f) flag:
$ bee run --filter="events,comm,node" ghcr.io/solo-io/bumblebee/opensnoop:0.0.7
$ bee run -f="events,comm,node" ghcr.io/solo-io/bumblebee/opensnoop:0.0.7

To run with multiple filters, use the --filter (or -f) flag multiple times:
$ bee run -f="events_hash,daddr,1.1.1.1" -f="events_ring,daddr,1.1.1.1" ghcr.io/solo-io/bumblebee/tcpconnect:0.0.7

If your program has histogram output, you can supply the buckets using --buckets (or -b) flag:
TODO(albertlockett) add a program w/ histogram buckets as example
$ bee run -b="events,[1,2,3,4,5]" ghcr.io/solo-io/bumblebee/TODO:0.0.7
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
	ctx, err := buildContext(cmd.Context(), opts.debug)
	if err != nil {
		return err
	}
	contextutils.LoggerFrom(ctx).Info("starting bee run")
	if opts.notty {
		pterm.DisableStyling()
	}

	progLocation := args[0]
	progReader, err := getProgram(ctx, opts.general, progLocation)
	if err != nil {
		return err
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit (check for sudo or setcap): %v", err)
	}

	promProvider, err := stats.NewPrometheusMetricsProvider(ctx, &stats.PrometheusOpts{Port: opts.promPort})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)
	parsedELF, err := progLoader.Parse(ctx, progReader)
	if err != nil {
		return fmt.Errorf("could not parse BPF program: %w", err)
	}

	watchMapOptions, err := parseWatchMapOptions(opts)
	if err != nil {
		contextutils.LoggerFrom(ctx).Errorf("could not parse watch map options: %v", err)
		return err
	}
	parsedELF.WatchedMapOptions = watchMapOptions

	tuiApp, err := buildTuiApp(&progLoader, progLocation, opts.filter, parsedELF)
	if err != nil {
		return err
	}
	loaderOpts := loader.LoadOptions{
		ParsedELF: parsedELF,
		Watcher:   tuiApp,
		PinMaps:   opts.pinMaps,
		PinProgs:  opts.pinProgs,
	}

	// bail out before starting TUI if context canceled
	if ctx.Err() != nil {
		contextutils.LoggerFrom(ctx).Info("before calling tui.Run() context is done")
		return ctx.Err()
	}
	if opts.notty {
		fmt.Println("Calling Load...")
		loaderOpts.Watcher = loader.NewNoopWatcher()
		err = progLoader.Load(ctx, &loaderOpts)
		return err
	} else {
		contextutils.LoggerFrom(ctx).Info("calling tui run()")
		err = tuiApp.Run(ctx, progLoader, &loaderOpts)
		contextutils.LoggerFrom(ctx).Info("after tui run()")
		return err
	}
}

func buildTuiApp(loader *loader.Loader, progLocation string, filterString []string, parsedELF *loader.ParsedELF) (*tui.App, error) {
	// TODO: add filter to UI
	filter, err := tui.BuildFilter(filterString, parsedELF.WatchedMaps)
	if err != nil {
		return nil, fmt.Errorf("could not build filter %w", err)
	}
	appOpts := tui.AppOpts{
		ProgLocation: progLocation,
		ParsedELF:    parsedELF,
		Filter:       filter,
	}
	app := tui.NewApp(&appOpts)
	return &app, nil
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

func buildContext(ctx context.Context, debug bool) (context.Context, error) {
	ctx, cancel := context.WithCancel(ctx)
	stopper = make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		fmt.Println("got sigterm or interrupt")
		cancel()
	}()

	var sugaredLogger *zap.SugaredLogger
	if debug {
		cfg := zap.NewDevelopmentConfig()
		cfg.OutputPaths = []string{"debug.log"}
		cfg.ErrorOutputPaths = []string{"debug.log"}
		logger, err := cfg.Build()
		if err != nil {
			return nil, fmt.Errorf("couldn't create zap logger: '%w'", err)
		}
		sugaredLogger = logger.Sugar()
	} else {
		sugaredLogger = zap.NewNop().Sugar()
	}
	ctx = contextutils.WithExistingLogger(ctx, sugaredLogger)

	return ctx, nil
}

func parseWatchMapOptions(runOpts *runOptions) (map[string]loader.WatchedMapOptions, error) {
	watchMapOptions := make(map[string]loader.WatchedMapOptions)

	for _, bucket := range runOpts.histBuckets {
		mapName, bucketLimits, err := parseBucket(bucket)
		if err != nil {
			return nil, err
		}
		watchMapOptions[mapName] = loader.WatchedMapOptions{
			HistBuckets: bucketLimits,
		}
	}

	for _, key := range runOpts.histValueKey {
		split := strings.Index(key, ",")
		if split == -1 {
			return nil, fmt.Errorf("could not parse hist-value-key: %s", key)
		}
		mapName := key[:split]
		valueKey := key[split+1:]
		if _, ok := watchMapOptions[mapName]; !ok {
			watchMapOptions[mapName] = loader.WatchedMapOptions{}
		}
		w := watchMapOptions[mapName]
		w.HistValueKey = valueKey
		watchMapOptions[mapName] = w
	}

	return watchMapOptions, nil
}

func parseBucket(bucket string) (string, []float64, error) {
	split := strings.Index(bucket, ",")
	if split == -1 {
		return "", nil, fmt.Errorf("could not parse bucket: %s", bucket)
	}

	mapName := bucket[:split]
	bucketLimits := bucket[split+1:]
	bucketLimits = strings.TrimPrefix(bucketLimits, "[")
	bucketLimits = strings.TrimSuffix(bucketLimits, "]")
	buckets := []float64{}

	for _, limit := range strings.Split(bucketLimits, ",") {
		bval, err := strconv.ParseFloat(limit, 64)
		if err != nil {
			return "", nil, fmt.Errorf("could not parse bucket: %s from buckets %s", limit, bucket)
		}
		buckets = append(buckets, bval)
	}

	return mapName, buckets, nil

}
