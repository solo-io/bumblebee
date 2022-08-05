package pull

import (
	"context"
	"fmt"

	"github.com/pterm/pterm"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/spf13/cobra"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

type pullOptions struct {
	general *options.GeneralOptions
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	pullOpts := &pullOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull an OCI image from a registry.",
		Args:  cobra.ExactArgs(1), // Ref
		RunE: func(cmd *cobra.Command, args []string) error {
			return pull(cmd.Context(), pullOpts.general, args[0])
		},
	}

	return cmd
}

func pull(ctx context.Context, opts *options.GeneralOptions, ref string) error {

	localRegistry, err := content.NewOCI(opts.OCIStorageDir)
	if err != nil {
		return err
	}

	remoteRegistry, err := content.NewRegistry(opts.AuthOptions.ToRegistryOptions())
	if err != nil {
		return err
	}

	pullSpinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Pulling image %s from remote registry", ref))
	_, err = oras.Copy(
		ctx,
		remoteRegistry,
		ref,
		localRegistry,
		"",
		oras.WithAllowedMediaTypes(spec.AllowedMediaTypes()),
		oras.WithPullByBFS,
	)
	if err != nil {
		pullSpinner.UpdateText(fmt.Sprintf("Failed to pull image %s", ref))
		pullSpinner.Fail()
		return err
	}
	pullSpinner.Success()
	return nil

}
