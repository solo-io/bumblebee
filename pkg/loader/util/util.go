package util

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const (
	counterMapType = "counter"
	gaugeMapType   = "gauge"
	printMapType   = "print"
)

func IsPrintMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, printMapType)
}

func IsGaugeMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, gaugeMapType)
}

func IsCounterMap(spec *ebpf.MapSpec) bool {
	return strings.Contains(spec.SectionName, counterMapType)
}

func IsTrackedMap(spec *ebpf.MapSpec) bool {
	return IsCounterMap(spec) || IsGaugeMap(spec) || IsPrintMap(spec)
}

func GetLabelsForBtfStruct(structKey *btf.Struct) []string {
	keys := make([]string, 0, len(structKey.Members))
	for _, v := range structKey.Members {
		keys = append(keys, v.Name)
	}
	return keys
}

func GetLabelsForHashMapKey(mapSpec *ebpf.MapSpec) ([]string, error) {
	structKey, ok := mapSpec.BTF.Key.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("hash map keys can only be a struct, found %s", mapSpec.BTF.Value.String())
	}

	return GetLabelsForBtfStruct(structKey), nil
}
