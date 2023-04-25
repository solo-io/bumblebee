package cli

import (
	"path/filepath"

	dockercliconfig "github.com/docker/cli/cli/config"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/build"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/describe"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/initialize"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/list"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/login"
	package_cmd "github.com/solo-io/bumblebee/pkg/cli/internal/commands/package"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/pull"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/push"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/run"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/tag"
	"github.com/solo-io/bumblebee/pkg/cli/internal/commands/version"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/spf13/cobra"
)

func Bee() *cobra.Command {
	cmd := &cobra.Command{
		Use: "bee",
	}
	opts := options.NewGeneralOptions(cmd.PersistentFlags())

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if opts.AuthOptions.CredentialsFiles == nil {
			// use config file first first and then dockers, the enables:
			// - the first one will be used for writing (i.e. in login)
			// but users can also re-use their existing credentials from docker login.
			opts.AuthOptions.CredentialsFiles = []string{
				filepath.Join(opts.ConfigDir, dockercliconfig.ConfigFileName),
				filepath.Join(dockercliconfig.Dir(), dockercliconfig.ConfigFileName),
			}
		}
	}

	cmd.AddCommand(
		build.Command(opts),
		package_cmd.Command(opts),
		run.Command(opts),
		initialize.Command(),
		push.Command(opts),
		pull.Command(opts),
		list.Command(opts),
		tag.Command(opts),
		describe.Command(opts),
		login.Command(opts),
		version.Command(opts),
	)

	return cmd
}
