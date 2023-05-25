// Package _map because map is a primitive
package bpfmap

import (
	"github.com/spf13/cobra"

	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
)

func showCmd(opts *options.GeneralOptions) *cobra.Command {
	runOptions := &runOptions{
		general: opts,
	}
	cmd := cobra.Command{
		Use:   "show PINNED_MAP",
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

	return &cmd
}
