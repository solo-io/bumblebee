package version

import (
	"fmt"

	"github.com/solo-io/bumblebee/internal/version"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type versionOptions struct {
	general *options.GeneralOptions
}

func addToFlags(flags *pflag.FlagSet, opts *versionOptions) {
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	versionOpts := &versionOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display bee Version Information.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", version.Version)
			return nil
		},
		SilenceUsage: true,
	}
	addToFlags(cmd.PersistentFlags(), versionOpts)
	return cmd
}
