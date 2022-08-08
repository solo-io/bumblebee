package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/go-utils/contextutils"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/pkg/content"
)

type ProbeCache interface {
	UpdateAll(ctx context.Context, nodeLabels map[string]string) error
	UpdateProbe(ctx context.Context, probe *probes_bumblebee_io_v1alpha1.Probe) error
	Clean(key types.NamespacedName)
}

func NewProbeCache(
	cacheDir string,
	nodeLabels map[string]string,
	progLoader loader.Loader,
) *probeCache {
	ap := &atomic.Pointer[map[string]string]{}
	ap.Store(&nodeLabels)
	return &probeCache{
		probes:     &sync.Map{},
		nodeLabels: ap,
		progLoader: progLoader,
	}
}

type probeCache struct {
	cacheDir   string
	probes     *sync.Map
	nodeLabels *atomic.Pointer[map[string]string]
	progLoader loader.Loader
}

func (r *probeCache) UpdateAll(ctx context.Context, nodeLabels map[string]string) error {
	r.nodeLabels.Store(&nodeLabels)
	r.probes.Range(func(key, value interface{}) bool {
		rp := value.(*cachedProbe)
		// If the probe node selector matches the current node, and isn't yet running, start it.
		if labels.SelectorFromSet(rp.probe.Spec.NodeSelector).Matches(labels.Set(nodeLabels)) && !rp.running {

		}

		// Always finish list
		return true
	})
	return nil
}

func (r *probeCache) UpdateProbe(ctx context.Context, probe *probes_bumblebee_io_v1alpha1.Probe) error {
	key := types.NamespacedName{Name: probe.Name, Namespace: probe.Namespace}
	currentLabels := *(r.nodeLabels.Load())

	if existing, ok := r.Probe(key); ok {
		contextutils.LoggerFrom(ctx).Debug("checking existing probe for potential update")
		// If the probe now has a new image, cancel the old one, and start a new one.
		if existing.probe.Spec.ImageName != probe.Spec.ImageName {
			contextutils.LoggerFrom(ctx).Debug("Existing probe has a different image, closing old one, and starting new one")
			r.Clean(key)
			// Attempt to restart program
			if err := r.startProgram(ctx, probe); err != nil {
				return err
			}
		}

	} else {
		// Check if the node selcetor matches the node labels
		if labels.SelectorFromSet(probe.Spec.NodeSelector).Matches(labels.Set(currentLabels)) {
			// If so attempt to start the program
			contextutils.LoggerFrom(ctx).Debug("Attempting to start program")
			if err := r.startProgram(ctx, probe); err != nil {
				return err
			}
		} else {
			contextutils.LoggerFrom(ctx).Debug("Node selector doesn't match current node, not starting program")
		}
	}

	return nil
}

func (r *probeCache) Store(key types.NamespacedName, rp *cachedProbe) {
	r.probes.Store(key, rp)
}

func (r *probeCache) Clean(key types.NamespacedName) {
	val, ok := r.probes.LoadAndDelete(key)
	if !ok {
		return
	}
	rp := val.(*cachedProbe)
	if rp.running {
		rp.cancel()
	}
}

func (r *probeCache) Probe(key types.NamespacedName) (*cachedProbe, bool) {
	val, ok := r.probes.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*cachedProbe), ok
}

type cachedProbe struct {
	probe *probes_bumblebee_io_v1alpha1.Probe

	// Will be set to true if the probe is running
	running bool
	// Will only be non-nil if running == true
	cancel context.CancelFunc
}

func (p *probeCache) startProgram(ctx context.Context, obj *probes_bumblebee_io_v1alpha1.Probe) error {

	rd, err := p.getProgram(ctx, obj.Spec.GetImageName())
	if err != nil {
		return err
	}
	parsedELF, err := p.progLoader.Parse(ctx, rd)
	if err != nil {
		return fmt.Errorf("could not parse BPF program: %w", err)
	}

	loaderOpts := &loader.LoadOptions{
		ParsedELF: parsedELF,
		Watcher:   loader.NewNoopWatcher(),
		AdditionalLabels: map[string]string{
			"probe_name":      obj.Name,
			"probe_namespace": obj.Namespace,
		},
	}

	key := types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}

	nestedCtx, cancel := context.WithCancel(ctx)

	p.Store(key, &cachedProbe{
		probe:   obj.DeepCopy(),
		cancel:  cancel,
		running: true,
	})
	go func() {
		// always cancel the context to prevent leaking goroutines
		defer p.Clean(key)
		if err := p.progLoader.Load(nestedCtx, loaderOpts); err != nil && !errors.Is(err, context.Canceled) {
			contextutils.LoggerFrom(nestedCtx).Errorf("could not load BPF program: %v", err)
		}
	}()

	return nil
}

func (p *probeCache) getProgram(
	ctx context.Context,
	progLocation string,
) (io.ReaderAt, error) {
	client := spec.NewEbpfOCICLient()
	prog, err := spec.TryFromLocal(
		ctx,
		progLocation,
		p.cacheDir,
		client,
		// Handle Auth
		content.RegistryOptions{},
	)
	if err != nil {
		if err, ok := err.(interface {
			StackTrace() errors.StackTrace
		}); ok {
			for _, f := range err.StackTrace() {
				fmt.Printf("%+s:%d\n", f, f)
			}
		}

		return nil, err
	}
	return bytes.NewReader(prog.ProgramFileBytes), nil
}
