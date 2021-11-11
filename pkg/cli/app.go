package cli

import (
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/build"
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/initialize"
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/list"
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/pull"
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/push"
	"github.com/solo-io/gloobpf/pkg/cli/internal/commands/run"
	"github.com/solo-io/gloobpf/pkg/cli/internal/options"
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
		pull.Command(opts),
		list.Command(opts),
	)
	return cmd
}
