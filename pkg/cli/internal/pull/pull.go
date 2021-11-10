package pull

import (
	"context"
	"fmt"

	"github.com/pterm/pterm"
	"github.com/solo-io/gloobpf/pkg/cli/internal/options"
	"github.com/solo-io/gloobpf/pkg/packaging"
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
		Use:  "pull",
		Args: cobra.ExactArgs(1), // Ref
		RunE: func(cmd *cobra.Command, args []string) error {
			return pull(cmd.Context(), pullOpts.general, args[0])
		},
	}

	return cmd
}

func pull(ctx context.Context, opts *options.GeneralOptions, ref string) error {
	pterm.Info.Printfln("Pulling eBPF image %s", ref)

	localRegistry, err := content.NewOCI(opts.OCIStorageDir)
	if err != nil {
		return err
	}

	remoteRegistry, err := content.NewRegistry(opts.AuthOptions.ToRegistryOptions())
	if err != nil {
		return err
	}

	pullSpinner, _ := pterm.DefaultSpinner.Start("Pulling image %s from remote registry", ref)
	_, err = oras.Copy(
		ctx,
		localRegistry,
		ref,
		remoteRegistry,
		"",
		oras.WithAllowedMediaTypes(packaging.AllowedMediaTypes()),
	)
	if err != nil {
		pullSpinner.UpdateText(fmt.Sprintf("Failed to pull image %s", ref))
		pullSpinner.Fail()
		return err
	}
	pullSpinner.Success()
	return nil

}
