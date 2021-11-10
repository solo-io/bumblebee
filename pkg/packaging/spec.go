package packaging

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

const (
	configMediaType = "application/ebpf.oci.image.config.v1+json"
	eBPFMediaType   = "application/ebpf.oci.image.program.v1+binary"

	ebpfFileName = "program.o"
	configName   = "config.json"
)

type EbpfPackage struct {
	// File content for eBPF compiled ELF file
	ProgramFileBytes []byte

	// (Optional) Human readable description
	Description string

	// (Optional) Package author
	Author string
}

type EbpfRegistry interface {
	Push(ctx context.Context, ref string, pkg *EbpfPackage) error
	Pull(ctx context.Context, ref string) (*EbpfPackage, error)
}

func NewEbpfRegistry(
	registry *content.Registry,
) EbpfRegistry {
	return &ebpfResgistry{
		registry: registry,
	}
}

type ebpfResgistry struct {
	registry *content.Registry
}

func allowedMediaTypes() []string {
	return []string{eBPFMediaType, configMediaType}
}

func (e *ebpfResgistry) Push(ctx context.Context, ref string, pkg *EbpfPackage) error {

	memoryStore := content.NewMemory()

	progDesc, err := memoryStore.Add(ebpfFileName, eBPFMediaType, pkg.ProgramFileBytes)
	if err != nil {
		return err
	}

	configAnnotations := map[string]string{
		ocispec.AnnotationTitle: configName,
	}
	config, configDesc, err := content.GenerateConfig(configAnnotations)
	if err != nil {
		return err
	}
	memoryStore.Set(configDesc, config)

	manifestAnnotations := map[string]string{
		ocispec.AnnotationDescription: pkg.Description,
		ocispec.AnnotationAuthors:     pkg.Author,
	}

	manifest, manifestDesc, err := content.GenerateManifest(&configDesc, manifestAnnotations, progDesc)
	if err != nil {
		return err
	}

	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
	if err != nil {
		return err
	}

	_, err = oras.Copy(
		ctx,
		memoryStore,
		ref,
		e.registry,
		"",
		oras.WithAllowedMediaTypes(allowedMediaTypes()),
	)
	return err
}

func (e *ebpfResgistry) Pull(ctx context.Context, ref string) (*EbpfPackage, error) {
	memoryStore := content.NewMemory()
	_, err := oras.Copy(
		ctx,
		e.registry,
		ref,
		memoryStore,
		"",
		oras.WithAllowedMediaTypes(allowedMediaTypes()),
	)
	if err != nil {
		return nil, err
	}

	_, manifestDesc, err := memoryStore.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	_, manifestBytes, ok := memoryStore.Get(manifestDesc)
	if !ok {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}

	_, ebpfBytes, ok := memoryStore.GetByName(ebpfFileName)
	if !ok {
		return nil, errors.New("could not find ebpf bytes in manifest")
	}

	return &EbpfPackage{
		ProgramFileBytes: ebpfBytes,
		Description:      manifest.Annotations[ocispec.AnnotationDescription],
		Author:           manifest.Annotations[ocispec.AnnotationAuthors],
	}, nil
}

// GenerateConfig generates a blank config with optional annotations.
func buildConfigDescriptor(byt []byte, annotations map[string]string) (ocispec.Descriptor, error) {
	dig := digest.FromBytes(byt)
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[ocispec.AnnotationTitle] = configName
	config := ocispec.Descriptor{
		MediaType:   configMediaType,
		Digest:      dig,
		Size:        int64(len(byt)),
		Annotations: annotations,
	}
	return config, nil
}
