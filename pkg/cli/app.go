package cli

import (
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/build"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/describe"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/initialize"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/list"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/pull"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/push"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/run"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/tag"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/internal/version"
	"github.com/spf13/cobra"
)

func Bee() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bee",
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
		tag.Command(opts),
		describe.Command(opts),
	)
	return cmd
}
