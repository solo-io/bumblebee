package packaging

import (
	"context"
	"errors"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

const (
	configMediaType = "application/ebpf.oci.image.config.v1+json"
	eBPFMediaType   = "binary/ebpf.solo.io.v1"

	ebpfFileName = "program.o"
)

type EbpfPackage struct {
	// File content for eBPF compiled ELF file
	ProgramFileBytes []byte
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

func (e *ebpfResgistry) Push(ctx context.Context, ref string, pkg *EbpfPackage) error {

	memoryStore := content.NewMemory()

	progDesc, err := memoryStore.Add(ebpfFileName, eBPFMediaType, pkg.ProgramFileBytes)
	if err != nil {
		return err
	}

	// TODO: update with config when/if we need it
	manifest, manifestDesc, config, configDesc, err := content.GenerateManifestAndConfig(
		nil,
		nil,
		progDesc,
	)
	if err != nil {
		return err
	}

	memoryStore.Set(configDesc, config)

	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
	if err != nil {
		return err
	}

	_, err = oras.Copy(ctx, memoryStore, ref, e.registry, "")
	return err
}

func (e *ebpfResgistry) Pull(ctx context.Context, ref string) (*EbpfPackage, error) {
	memoryStore := content.NewMemory()
	_, err := oras.Copy(ctx, e.registry, ref, memoryStore, "")
	if err != nil {
		return nil, err
	}

	_, ebpfBytes, ok := memoryStore.GetByName(ebpfFileName)
	if !ok {
		return nil, errors.New("could not find ebpf bytes in manifest")
	}

	return &EbpfPackage{
		ProgramFileBytes: ebpfBytes,
	}, nil
}
