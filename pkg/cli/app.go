package cli

import (
	"github.com/solo-io/gloobpf/pkg/cli/internal/build"
	"github.com/solo-io/gloobpf/pkg/cli/internal/initialize"
	"github.com/solo-io/gloobpf/pkg/cli/internal/options"
	"github.com/solo-io/gloobpf/pkg/cli/internal/push"
	"github.com/solo-io/gloobpf/pkg/cli/internal/run"
	"github.com/solo-io/gloobpf/pkg/internal/version"
	"github.com/spf13/cobra"
)

func EbpfCtl() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ebpfctl",
		Version: version.Version,
	}

	opts := options.NewGeneralOptions(cmd.PersistentFlags())

	cmd.AddCommand(
		build.Command(opts),
		run.Command(opts),
		initialize.Command(),
		push.Command(opts),
	)
	return cmd
}
