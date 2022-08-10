package spec

import (
	"context"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

type PullOpts struct {
	Ref             string
	LocalStorageDir string
	Client          EbpfOCICLient
	content.RegistryOptions
}

type PullFunc func(ctx context.Context, opts PullOpts) (*EbpfPackage, error)

func TryFromLocal(
	ctx context.Context,
	opts PullOpts,
) (*EbpfPackage, error) {
	return pullImage(ctx, opts, true, true)
}

func Pull(
	ctx context.Context,
	opts PullOpts,
) (*EbpfPackage, error) {
	return pullImage(ctx, opts, false, true)
}

func NeverPull(
	ctx context.Context,
	opts PullOpts,
) (*EbpfPackage, error) {
	return pullImage(ctx, opts, false, false)
}

func pullImage(
	ctx context.Context,
	opts PullOpts,
	tryFromLocal, attemptToPull bool,
) (*EbpfPackage, error) {

	if opts.LocalStorageDir == "" {
		opts.LocalStorageDir = EbpfImageDir
	}

	localRegistry, err := content.NewOCI(opts.LocalStorageDir)
	if err != nil {
		return nil, err
	}
	if tryFromLocal {
		if _, _, err := localRegistry.Resolve(ctx, opts.Ref); err == nil {
			// If we find the image locally, return it
			if prog, err := opts.Client.Pull(ctx, opts.Ref, localRegistry); err == nil {
				return prog, nil
			}
		}
	}

	if attemptToPull {

		remoteRegistry, err := content.NewRegistry(opts.RegistryOptions)
		if err != nil {
			return nil, err
		}

		_, err = oras.Copy(
			ctx,
			remoteRegistry,
			opts.Ref,
			localRegistry,
			"",
			oras.WithAllowedMediaTypes(AllowedMediaTypes()),
			oras.WithPullByBFS,
		)
		if err != nil {
			return nil, err
		}
	}

	// program should now be in the local cache after above copy
	return opts.Client.Pull(ctx, opts.Ref, localRegistry)
}
