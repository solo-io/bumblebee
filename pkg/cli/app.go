package cli

import (
	"github.com/solo-io/gloobpf/pkg/cli/internal/build"
	"github.com/solo-io/gloobpf/pkg/cli/internal/initialize"
	"github.com/solo-io/gloobpf/pkg/cli/internal/run"
	"github.com/solo-io/gloobpf/pkg/internal/version"
	"github.com/spf13/cobra"
)

type options struct {
	build *build.BuildOptions
	run   *run.RunOptions
}

func newOptions() *options {
	return &options{
		build: &build.BuildOptions{},
		run:   &run.RunOptions{},
	}
}

func EbpfCtl() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ebpfctl",
		Version: version.Version,
	}

	opts := newOptions()
	cmd.AddCommand(
		build.BuildCommand(opts.build),
		run.RunCommand(opts.run),
		initialize.InitCommand(),
	)
	return cmd
}
