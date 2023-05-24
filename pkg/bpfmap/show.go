package bpfmap

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func Show(filename string) error{
	m, err := ebpf.LoadPinnedMap(filename, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("could not load pinned map: %w", err)
	}

	iter := m.Iterate()
	var key, value []byte
	for iter.Next(&key, &value) {

	}

	err = iter.Err()
	if err != nil {
		return fmt.Errorf("error occurred during map iteration: %w", err)
	}

	return nil
}