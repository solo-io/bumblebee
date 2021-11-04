package packaging

import (
	"context"
	"fmt"
	"os"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

const EBPFMediaType = "ebof.solo.io/v1"

func getLocalRegistryHostname() string {
	hostname := "localhost"
	if v := os.Getenv("LOCAL_REGISTRY_HOSTNAME"); v != "" {
		hostname = v
	}
	return hostname
}

// Dead simple example code copied from: https://github.com/oras-project/oras-go/blob/v0.5.0/examples/simple/simple_push_pull.go
func doThing() error {
	ref := fmt.Sprintf("%s:5000/oras:test", getLocalRegistryHostname())
	fileName := "hello.txt"
	fileContent := []byte("Hello World!\n")

	ctx := context.Background()

	// Push file(s) w custom mediatype to registry
	memoryStore := content.NewMemory()
	desc, err := memoryStore.Add(fileName, EBPFMediaType, fileContent)
	if err != nil {
		return err
	}

	manifest, manifestDesc, config, configDesc, err := content.GenerateManifestAndConfig(nil, nil, desc)
	if err != nil {
		return err
	}
	memoryStore.Set(configDesc, config)
	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
	if err != nil {
		return err
	}
	registry, err := content.NewRegistry(content.RegistryOptions{PlainHTTP: true})
	fmt.Printf("Pushing %s to %s...\n", fileName, ref)
	desc, err = oras.Copy(ctx, memoryStore, ref, registry, "")
	if err != nil {
		return err
	}
	fmt.Printf("Pushed to %s with digest %s\n", ref, desc.Digest)

	// Pull file(s) from registry and save to disk
	fmt.Printf("Pulling from %s and saving to %s...\n", ref, fileName)
	fileStore := content.NewFile("")
	defer fileStore.Close()
	allowedMediaTypes := []string{EBPFMediaType}
	desc, err = oras.Copy(ctx, registry, ref, fileStore, "", oras.WithAllowedMediaTypes(allowedMediaTypes))
	if err != nil {
		return err
	}
	fmt.Printf("Pulled from %s with digest %s\n", ref, desc.Digest)
	fmt.Printf("Try running 'cat %s'\n", fileName)
	return nil
}
