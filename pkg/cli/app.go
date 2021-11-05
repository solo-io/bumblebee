package cli

import (
	"github.com/solo-io/gloobpf/pkg/cli/internal/build"
	"github.com/solo-io/gloobpf/pkg/cli/internal/run"
	"github.com/spf13/cobra"
)

func EbpfCtl() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ebpfctl",
	}

	cmd.AddCommand(
		build.BuildCommand(),
		run.RunCommand(),
	)
	return cmd
}
