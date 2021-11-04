package packaging

import (
	"context"
	"errors"
	"os"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
)

const (
	configMediaType = "application/ebpf.oci.image.config.v1+json"
	EBPFMediaType   = "ebpf.solo.io.progfile/v1"
	BTFMediaType    = "ebpf.solo.io.btftypes/v1"

	ebpfFileName = "program.o"
	btfFileName  = "types.btf"
)

type EbpfPackage struct {
	// File content for eBPF compiled ELF file
	ProgramFileBytes []byte
	// File content for BTF types
	BtfTypeBytes []byte

	Annotations map[string]string
}

type EbpfRegistry interface {
	Push(ctx context.Context)
	Pull(ctx context.Context)
}

type ebpfResgistry struct {
	registryRef string
	registry    *content.Registry
}

func (e *ebpfResgistry) Push(ctx context.Context, pkg *EbpfPackage) error {

	memoryStore := content.NewMemory()

	progDesc, err := memoryStore.Add(ebpfFileName, EBPFMediaType, pkg.ProgramFileBytes)
	if err != nil {
		return err
	}

	btfDesc, err := memoryStore.Add(btfFileName, BTFMediaType, pkg.BtfTypeBytes)
	if err != nil {
		return err
	}

	// TODO: update with config when/if we need it
	manifest, manifestDesc, config, configDesc, err := content.GenerateManifestAndConfig(
		pkg.Annotations,
		nil,
		progDesc, btfDesc,
	)
	if err != nil {
		return err
	}
	memoryStore.Set(configDesc, config)

	err = memoryStore.StoreManifest(e.registryRef, manifestDesc, manifest)
	if err != nil {
		return err
	}

	_, err = oras.Copy(ctx, memoryStore, e.registryRef, e.registry, "")
	return err
}

func (e *ebpfResgistry) Pull(ctx context.Context) (*EbpfPackage, error) {
	memoryStore := content.NewMemory()
	desc, err := oras.Copy(ctx, e.registry, e.registryRef, memoryStore, "")
	if err != nil {
		return nil, err
	}

	_, btfBytes, ok := memoryStore.GetByName(btfFileName)
	if !ok {
		return nil, errors.New("could not find btf bytes in manifest")
	}
	_, ebpfBytes, ok := memoryStore.GetByName(ebpfFileName)
	if !ok {
		return nil, errors.New("could not find ebpf bytes in manifest")
	}

	return &EbpfPackage{
		ProgramFileBytes: ebpfBytes,
		BtfTypeBytes:     btfBytes,
		Annotations:      desc.Annotations,
	}, nil
}

func getLocalRegistryHostname() string {
	hostname := "localhost"
	if v := os.Getenv("LOCAL_REGISTRY_HOSTNAME"); v != "" {
		hostname = v
	}
	return hostname
}
