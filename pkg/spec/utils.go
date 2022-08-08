package spec

import (
	"context"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

func TryFromLocal(
	ctx context.Context,
	ref, localStorageDir string,
	client EbpfOCICLient,
	auth content.RegistryOptions,
) (*EbpfPackage, error) {
	return pullImage(ctx, ref, localStorageDir, client, auth, true, true)
}

func Pull(
	ctx context.Context,
	ref, localStorageDir string,
	client EbpfOCICLient,
	auth content.RegistryOptions,
) (*EbpfPackage, error) {
	return pullImage(ctx, ref, localStorageDir, client, auth, false, true)
}

func NeverPull(
	ctx context.Context,
	ref, localStorageDir string,
	client EbpfOCICLient,
	auth content.RegistryOptions,
) (*EbpfPackage, error) {
	return pullImage(ctx, ref, localStorageDir, client, auth, false, false)
}

func pullImage(
	ctx context.Context,
	ref, localStorageDir string,
	client EbpfOCICLient,
	auth content.RegistryOptions,
	tryFromLocal, attemptToPull bool,
) (*EbpfPackage, error) {

	if localStorageDir == "" {
		localStorageDir = EbpfImageDir
	}

	localRegistry, err := content.NewOCI(localStorageDir)
	if err != nil {
		return nil, err
	}
	if tryFromLocal {
		if _, _, err := localRegistry.Resolve(ctx, ref); err == nil {
			// If we find the image locally, return it
			if prog, err := client.Pull(ctx, ref, localRegistry); err == nil {
				return prog, nil
			}
		}
	}

	if attemptToPull {

		remoteRegistry, err := content.NewRegistry(auth)
		if err != nil {
			return nil, err
		}

		_, err = oras.Copy(
			ctx,
			remoteRegistry,
			ref,
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
	return client.Pull(ctx, ref, localRegistry)
}
