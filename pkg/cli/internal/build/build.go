package build

import (
	"fmt"

	"github.com/solo-io/gloobpf/pkg/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BuildOptions struct {
	BuildImage string
}

func addToFlags(flags *pflag.FlagSet, opts *BuildOptions) {
	flags.StringVarP(&opts.BuildImage, "build-image", "i", fmt.Sprintf("gcr.io/gloobpf/bpfbuilder:%s", version.Version), "")
}

func BuildCommand(opts *BuildOptions) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "build",
		Aliases: []string{"b"},
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// arg1 = file to compile
			// arg2 = image/file to save to
			return nil
		},
	}

	// Init flags
	addToFlags(cmd.PersistentFlags(), opts)

	return cmd
}
