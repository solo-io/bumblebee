package tag

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/pterm/pterm"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/spf13/cobra"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

type tagOptions struct {
	general *options.GeneralOptions
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	tagOpts := &tagOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:  "tag",
		Args: cobra.ExactArgs(2), // source, target ref
		RunE: func(cmd *cobra.Command, args []string) error {
			return tag(cmd.Context(), tagOpts.general, args[0], args[1])
		},
		Hidden: true, // TODO: unhide this when it works, currently moves, not copies
	}

	return cmd
}

func tag(
	ctx context.Context,
	opts *options.GeneralOptions,
	sourceRef, targetRef string,
) error {

	localRegistry, err := content.NewOCI(opts.OCIStorageDir)
	if err != nil {
		return err
	}

	_, desc, err := localRegistry.Resolve(ctx, sourceRef)
	if err != nil {
		return err
	}

	reader, err := localRegistry.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer reader.Close()

	byt, _ := ioutil.ReadAll(reader)

	memoryRegister := content.NewMemory()
	if err := memoryRegister.StoreManifest(targetRef, desc, byt); err != nil {
		return err
	}

	tagSpinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Tagging image %s as %s", sourceRef, targetRef))
	_, err = oras.Copy(
		ctx,
		memoryRegister,
		targetRef,
		localRegistry,
		targetRef,
		oras.WithAllowedMediaTypes(spec.AllowedMediaTypes()),
	)
	if err != nil {
		tagSpinner.UpdateText(fmt.Sprintf("Failed to tag image %s", sourceRef))
		tagSpinner.Fail()
		return err
	}
	tagSpinner.Success()
	return nil

}
