package tag

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/solo-io/bumblebee/pkg/cli/internal/options"
	"github.com/spf13/cobra"
	"oras.land/oras-go/pkg/content"
)

type tagOptions struct {
	general *options.GeneralOptions
}

func Command(opts *options.GeneralOptions) *cobra.Command {
	tagOpts := &tagOptions{
		general: opts,
	}
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Add an additional name to a local OCI image.",
		Args:  cobra.ExactArgs(2), // source, target ref
		RunE: func(cmd *cobra.Command, args []string) error {
			return tag(cmd.Context(), tagOpts.general, args[0], args[1])
		},
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

	if desc.Annotations != nil {
		annotations := desc.Annotations
		// note: we have to copy the map, so we don't mess with the original descriptor map
		desc.Annotations = make(map[string]string)
		for k, v := range annotations {
			if k != ocispec.AnnotationRefName {
				desc.Annotations[k] = v
			}
		}
	}

	localRegistry.AddReference(targetRef, desc)
	err = localRegistry.SaveIndex()
	return err
}
