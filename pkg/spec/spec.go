package spec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
	"oras.land/oras-go/pkg/target"
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
	// Human readable description of the program
	Description string
	// Author(s) of the program
	Authors string
	// Platform this was built on
	Platform *ocispec.Platform
	// SHA256 hash of the image.
	// Does not need to be set before Push.
	SHA256 string
	// Nested config object
	EbpfConfig
}

type EbpfConfig struct{}

type EbpfOCICLient interface {
	Push(ctx context.Context, ref string, registry target.Target, pkg *EbpfPackage) error
	Pull(ctx context.Context, ref string, registry target.Target) (*EbpfPackage, error)
}

func NewEbpfOCICLient() EbpfOCICLient {
	return &ebpfOCIClient{}
}

type ebpfOCIClient struct{}

func AllowedMediaTypes() []string {
	return []string{eBPFMediaType, configMediaType}
}

func (e *ebpfOCIClient) Push(
	ctx context.Context,
	ref string,
	registry target.Target,
	pkg *EbpfPackage,
) error {

	memoryStore := content.NewMemory()

	progDesc, err := memoryStore.Add(ebpfFileName, eBPFMediaType, pkg.ProgramFileBytes)
	if err != nil {
		return err
	}

	configByt, err := json.Marshal(pkg.EbpfConfig)
	if err != nil {
		return err
	}

	configDesc, err := buildConfigDescriptor(configByt, nil)
	if err != nil {
		return err
	}

	memoryStore.Set(configDesc, configByt)

	manifestAnnotations := make(map[string]string)
	if pkg.Authors != "" {
		manifestAnnotations[ocispec.AnnotationAuthors] = pkg.Authors
	}
	if pkg.Description != "" {
		manifestAnnotations[ocispec.AnnotationDescription] = pkg.Description
	}

	manifest, manifestDesc, err := content.GenerateManifest(
		&configDesc,
		manifestAnnotations,
		progDesc,
	)
	if err != nil {
		return err
	}

	manifestDesc.Platform = pkg.Platform

	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
	if err != nil {
		return err
	}

	_, err = oras.Copy(
		ctx,
		memoryStore,
		ref,
		registry,
		"",
		oras.WithAllowedMediaTypes(AllowedMediaTypes()),
		oras.WithPullByBFS,
	)
	return err
}

func (e *ebpfOCIClient) Pull(
	ctx context.Context,
	ref string,
	registry target.Target) (*EbpfPackage, error) {
	memoryStore := content.NewMemory()

	manifestDesc, err := oras.Copy(
		ctx,
		registry,
		ref,
		memoryStore,
		"",
		oras.WithAllowedMediaTypes(AllowedMediaTypes()),
	)
	if err != nil {
		return nil, err
	}

	_, ebpfBytes, ok := memoryStore.GetByName(ebpfFileName)
	if !ok {
		return nil, errors.New("could not find ebpf bytes in manifest")
	}

	_, configBytes, ok := memoryStore.GetByName(configName)
	if !ok {
		return nil, errors.New("could not find ebpf bytes in manifest")
	}

	var cfg EbpfConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, err
	}

	_, manifestBytes, ok := memoryStore.Get(manifestDesc)
	if !ok {
		return nil, errors.New("could not find manifest")
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("could not unmarshal manifest bytes: %w", err)
	}

	return &EbpfPackage{
		ProgramFileBytes: ebpfBytes,
		Description:      manifest.Annotations[ocispec.AnnotationDescription],
		Authors:          manifest.Annotations[ocispec.AnnotationAuthors],
		EbpfConfig:       cfg,
		Platform:         manifestDesc.Platform,
		SHA256:           string(manifestDesc.Digest),
	}, nil
}

// GenerateConfig generates a blank config with optional annotations.
func buildConfigDescriptor(
	byt []byte,
	annotations map[string]string,
) (ocispec.Descriptor, error) {
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
