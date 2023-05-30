// Package _map because map is a primitive
package bpfmap

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
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

	m, err := ebpf.LoadPinnedMap(args[0], &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("could not load pinned map: %w", err)
	}

	iter := m.Iterate()
	m.ValueSize()
	var key, value interface{}
	keyColumn := newMapColumn("Key")
	valueColumn := newMapColumn("Value")
	for iter.Next(&key, &value) {
		keyColumn.values = append(keyColumn.values, key)
		valueColumn.values = append(valueColumn.values, value)
	}


	m.Type()

	err = iter.Err()
	if err != nil {
		return fmt.Errorf("error occurred during map iteration: %w", err)
	}

	tui.Table(keyColumn, valueColumn)

	return nil
}

type mapColumn struct {
	header string

	values []interface{}
}

func newMapColumn(header string) *mapColumn {
	return &mapColumn{
		header: header,
	}
}

func (d mapColumn) Header() string {
	return d.header
}

func (d mapColumn) GetRowValue(row int) string {
	if d.NumRows() <= row {
		return ""
	}

	return fmt.Sprintf("%v", d.values[row])
}

func (d mapColumn) SetRowValue(row int, value string) {
	if d.NumRows() <= row {
		return
	}

	d.values[row] = value
}

func (d mapColumn) NumRows() int {
	return len(d.values)
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
