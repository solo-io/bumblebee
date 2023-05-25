// Package _map because map is a primitive
package bpfmap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/bumblebee/pkg/tui"
	"github.com/solo-io/go-utils/contextutils"
)

/*

What I'd like to have functionality-wise:

* No args: shows the maps currently loaded into the system
  * cmd?
  * Some way to index those maps, to manipulate them
* A way to load a map from a pinned file
  * ebpf.LoadPinnedMap

*/

type runOptions struct {
	general *options.GeneralOptions

	debug bool
	// notty    bool
}

var stopper chan os.Signal

func addToFlags(flags *pflag.FlagSet, opts *runOptions) {
	flags.BoolVarP(&opts.debug, "debug", "d", false, "Create a log file 'debug.log' that provides debug logs of loader and TUI execution")
	// flags.BoolVar(&opts.notty, "no-tty", false, "Set to true for running without a tty allocated, so no interaction will be expected or rich output will done")
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	runOptions := &runOptions{
		general: opts,
	}
	cmd := cobra.Command{
		Use:   "map PINNED_MAP",
		Short: "dump content of pinned map",
		// TODO: fixup long description
		Long: `
The bee map command aids in visualizing and debugging map values for a program currently loaded into the kernel.
`,
		Args: cobra.ExactArgs(1), // Filename or image
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, runOptions)
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), runOptions)

	cmd.AddCommand(showCmd(opts))

	return &cmd
}

func run(cmd *cobra.Command, args []string, opts *runOptions) error {
	ctx, err := buildContext(cmd.Context(), opts.debug)
	if err != nil {
		return err
	}

	contextutils.LoggerFrom(ctx).Info("starting bee show")
	// if opts.notty {
	//   pterm.DisableStyling()
	// }

	// // Allow the current process to lock memory for eBPF resources.
	// if err := rlimit.RemoveMemlock(); err != nil {
	//   return fmt.Errorf("could not raise memory limit (check for sudo or setcap): %v", err)
	// }

	m, err := ebpf.LoadPinnedMap(args[0], &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("could not load pinned map: %w", err)
	}

	iter := m.Iterate()
	var key, value []byte
	for iter.Next(&key, &value) {

	}

	err = iter.Err()
	if err != nil {
		return fmt.Errorf("error occurred during map iteration: %w", err)
	}

	return nil
}

func buildTuiApp(
	progLocation string,
	filterString []string,
	parsedELF *loader.ParsedELF,
) (*tui.App, error) {
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
