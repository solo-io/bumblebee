package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/solo-io/bumblebee/pkg/loader/mapwatcher"
	"github.com/solo-io/bumblebee/pkg/loader/util"
	"github.com/solo-io/go-utils/contextutils"
)

type ParsedELF struct {
	Spec        *ebpf.CollectionSpec
	WatchedMaps map[string]mapwatcher.WatchedMap
}

type LoadOptions struct {
	ParsedELF *ParsedELF
	PinMaps   string
	PinProgs  string
}

type Loader interface {
	Parse(ctx context.Context, reader io.ReaderAt) (*ParsedELF, error)
	Load(ctx context.Context, opts *LoadOptions) (link.Link, map[string]*ebpf.Map, error)
}

func Parse(ctx context.Context, progReader io.ReaderAt) (*ParsedELF, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, err
	}

	for _, prog := range spec.Programs {
		if prog.Type == ebpf.UnspecifiedProgram {
			contextutils.LoggerFrom(ctx).Debug("Program %s does not specify a type", prog.Name)
		}
	}

	watchedMaps := make(map[string]mapwatcher.WatchedMap)
	for name, mapSpec := range spec.Maps {
		if !util.IsTrackedMap(mapSpec) {
			continue
		}

		watchedMap := mapwatcher.WatchedMap{
			Name:    name,
			BTF:     mapSpec.BTF,
			MapType: mapSpec.Type,
			MapSpec: mapSpec,
		}

		// TODO: Delete Hack if possible
		if watchedMap.MapType == ebpf.RingBuf || watchedMap.MapType == ebpf.PerfEventArray {
			if _, ok := mapSpec.BTF.Value.(*btf.Struct); !ok {
				return nil, fmt.Errorf("the `value` member for map '%v' must be set to struct you will be submitting to the ringbuf/eventarray", name)
			}
			mapSpec.BTF = nil
			mapSpec.ValueSize = 0
		}

		switch mapSpec.Type {
		case ebpf.RingBuf:
			structType := watchedMap.BTF.Value.(*btf.Struct)
			watchedMap.ValueStruct = structType
			labelKeys := util.GetLabelsForBtfStruct(structType)

			watchedMap.Labels = labelKeys
		case ebpf.Hash:
			labelKeys, err := util.GetLabelsForHashMapKey(mapSpec)
			if err != nil {
				return nil, err
			}

			watchedMap.Labels = labelKeys
		default:
			return nil, errors.New("unsupported map type")
		}

		watchedMaps[name] = watchedMap
	}

	loadOptions := ParsedELF{
		Spec:        spec,
		WatchedMaps: watchedMaps,
	}
	return &loadOptions, nil
}

func Load(ctx context.Context, opts *LoadOptions) (link.Link, map[string]*ebpf.Map, error) {
	// TODO: add invariant checks on opts
	contextutils.LoggerFrom(ctx).Info("enter Load()")

	// bail out before loading stuff into kernel if context canceled
	if ctx.Err() != nil {
		contextutils.LoggerFrom(ctx).Info("load entrypoint context is done")
		return nil, nil, ctx.Err()
	}

	if opts.PinMaps != "" {
		// Specify that we'd like to pin the referenced maps, or open them if already existing.
		for _, m := range opts.ParsedELF.Spec.Maps {
			// Do not pin/load read-only data
			if strings.HasSuffix(m.Name, ".rodata") {
				continue
			}

			// PinByName specifies that we should pin the map by name, or load it if it already exists.
			m.Pinning = ebpf.PinByName
		}
	}

	spec := opts.ParsedELF.Spec
	// Load our eBPF spec into the kernel
	coll, err := ebpf.NewCollectionWithOptions(opts.ParsedELF.Spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: opts.PinMaps,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	defer coll.Close()
	var progLink link.Link

	// For each program, add kprope/tracepoint
	for name, prog := range spec.Programs {
		select {
		case <-ctx.Done():
			contextutils.LoggerFrom(ctx).Info("while loading progs context is done")
			return nil, nil, ctx.Err()
		default:
			switch prog.Type {
			case ebpf.Kprobe:
				var err error
				if strings.HasPrefix(prog.SectionName, "kretprobe/") {
					progLink, err = link.Kretprobe(prog.AttachTo, coll.Programs[name])
					if err != nil {
						return nil, nil, fmt.Errorf("error attaching kretprobe '%v': %w", prog.Name, err)
					}
				} else {
					progLink, err = link.Kprobe(prog.AttachTo, coll.Programs[name])
					if err != nil {
						return nil, nil, fmt.Errorf("error attaching kprobe '%v': %w", prog.Name, err)
					}
				}
			case ebpf.TracePoint:
				var err error
				if strings.HasPrefix(prog.SectionName, "tracepoint/") {
					tokens := strings.Split(prog.AttachTo, "/")
					if len(tokens) != 2 {
						return nil, nil, fmt.Errorf("unexpected tracepoint section '%v'", prog.AttachTo)
					}
					progLink, err = link.Tracepoint(tokens[0], tokens[1], coll.Programs[name])
					if err != nil {
						return nil, nil, fmt.Errorf("error attaching to tracepoint '%v': %w", prog.Name, err)
					}
				}
			default:
				return nil, nil, errors.New("only kprobe programs supported")
			}

			if opts.PinProgs != "" {
				if err := createDir(ctx, opts.PinProgs, 0700); err != nil {
					return nil, nil, err
				}

				pinFile := filepath.Join(opts.PinProgs, prog.Name)
				if err := coll.Programs[name].Pin(pinFile); err != nil {
					progLink.Close()
					return nil, nil, fmt.Errorf("could not pin program '%s': %v", prog.Name, err)
				}
				fmt.Printf("Successfully pinned program '%v'\n", pinFile)
			}
		}
	}

	return progLink, coll.Maps, nil
}

func createDir(ctx context.Context, path string, perm os.FileMode) error {
	file, err := os.Stat(path)
	if os.IsNotExist(err) {
		contextutils.LoggerFrom(ctx).Info("path does not exist, creating pin directory: %s", path)
		return os.Mkdir(path, perm)
	} else if err != nil {
		return fmt.Errorf("could not create pin directory '%v': %w", path, err)
	} else if !file.IsDir() {
		return fmt.Errorf("pin location '%v' exists but is not a directory", path)
	}

	return nil
}
