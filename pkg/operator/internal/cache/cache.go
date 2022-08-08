package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/go-utils/contextutils"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/pkg/content"
)

// ProbeCache is a component resonsible for keeping track of probe resources.
type ProbeCache interface {
	// UpdateAll takes in a list of node labels and compares them against
	// The cached probe node selector. If the node selector matches the
	// current node, and isn't yet running, start it. Likewise if it's
	// running but shouldn't be, cancel it.
	UpdateAll(ctx context.Context, nodeLabels map[string]string) error
	// UpdateProbe adds or updates a single probe's lifecycle status in the cache.
	// If the image name has changed from it's existing one, the old one will be
	// cancelled, and the new one started.
	UpdateProbe(ctx context.Context, probe *probes_bumblebee_io_v1alpha1.Probe) error
	// Clean removes a probe from the cache. It will stop the probe if it is running.
	Clean(key types.NamespacedName)
}

// NewProbeCache creates a new probe cache.
func NewProbeCache(
	cacheDir string,
	nodeLabels map[string]string,
	progLoader loader.Loader,
) *probeCache {
	ap := &atomic.Pointer[map[string]string]{}
	ap.Store(&nodeLabels)
	return &probeCache{
		probes:     &atomicProbeMap{probes: &sync.Map{}},
		nodeLabels: ap,
		progLoader: progLoader,
	}
}

type probeCache struct {
	cacheDir   string
	probes     *atomicProbeMap
	nodeLabels *atomic.Pointer[map[string]string]
	progLoader loader.Loader
}

func (r *probeCache) UpdateAll(ctx context.Context, nodeLabels map[string]string) error {
	r.nodeLabels.Store(&nodeLabels)
	var multierr *multierror.Error
	r.probes.Range(func(key types.NamespacedName, probe *cachedProbe) bool {
		// If the probe node selector matches the current node, and isn't yet running, start it.
		if labels.SelectorFromSet(probe.probe.Spec.NodeSelector).Matches(labels.Set(nodeLabels)) && !probe.running {
			if err := startProgram(ctx, probe.probe, r.progLoader, r.probes, r.cacheDir); err != nil {
				multierr = multierror.Append(err)
			}
			// Continue iteration
			return true
		}

		// If the node selector matches the current node, and is running, cancel it.
		if !labels.SelectorFromSet(probe.probe.Spec.NodeSelector).Matches(labels.Set(nodeLabels)) && probe.running {
			r.probes.Clean(key)
			// Continue iteration
			return true
		}

		// Always finish list
		return true
	})
	return multierr.ErrorOrNil()
}

func (r *probeCache) UpdateProbe(ctx context.Context, probe *probes_bumblebee_io_v1alpha1.Probe) error {
	key := types.NamespacedName{Name: probe.Name, Namespace: probe.Namespace}
	currentLabels := *(r.nodeLabels.Load())

	// We have a predicate on updates such that only generation changes will trigger this function.
	// In practice, this means that only spec changes to the probe CR will trigger this function.
	// Currently on generation change a new probe needs to be started, with the exception of one case.
	// NodeSelector has changed, but the node's labels still match.
	if existing, ok := r.probes.Probe(key); ok {
		contextutils.LoggerFrom(ctx).Debug("checking existing probe for potential update")
		// If the probe now has a new image, cancel the old one, and start a new one.
		if existing.probe.Spec.ImageName != probe.Spec.ImageName {
			contextutils.LoggerFrom(ctx).Debug("Existing probe has a different image, closing old one, and starting new one")
			r.probes.Clean(key)
			// Attempt to restart program
			if err := startProgram(ctx, probe, r.progLoader, r.probes, r.cacheDir); err != nil {
				return err
			}
		}

	} else {
		// Check if the node selcetor matches the node labels
		if labels.SelectorFromSet(probe.Spec.NodeSelector).Matches(labels.Set(currentLabels)) {
			// If so attempt to start the program
			contextutils.LoggerFrom(ctx).Debug("Attempting to start program")
			if err := startProgram(ctx, probe, r.progLoader, r.probes, r.cacheDir); err != nil {
				return err
			}
		} else {
			contextutils.LoggerFrom(ctx).Debug("Node selector doesn't match current node, not starting program")
		}
	}

	return nil
}

func (p *probeCache) Clean(key types.NamespacedName) {
	p.probes.Clean(key)
}

type atomicProbeMap struct {
	probes *sync.Map
}

func (r *atomicProbeMap) Range(f func(key types.NamespacedName, val *cachedProbe) bool) {
	r.probes.Range(func(key, value interface{}) bool {
		return f(key.(types.NamespacedName), value.(*cachedProbe))
	})
}

func (r *atomicProbeMap) Store(key types.NamespacedName, rp *cachedProbe) {
	r.probes.Store(key, rp)
}

func (r *atomicProbeMap) Clean(key types.NamespacedName) {
	val, ok := r.probes.LoadAndDelete(key)
	if !ok {
		return
	}
	rp := val.(*cachedProbe)
	if rp.running {
		rp.cancel()
	}

	rp.running = false
	rp.cancel = nil

}

func (r *atomicProbeMap) Probe(key types.NamespacedName) (*cachedProbe, bool) {
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

func startProgram(
	ctx context.Context,
	obj *probes_bumblebee_io_v1alpha1.Probe,
	progLoader loader.Loader,
	probeMap *atomicProbeMap,
	cacheDir string,
) error {

	rd, err := getProgram(ctx, obj.Spec.GetImageName(), cacheDir)
	if err != nil {
		return err
	}
	parsedELF, err := progLoader.Parse(ctx, rd)
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

	probeMap.Store(key, &cachedProbe{
		probe:   obj.DeepCopy(),
		cancel:  cancel,
		running: true,
	})
	go func() {
		contextutils.LoggerFrom(nestedCtx).Debug("Starting program")
		// always cancel the context to prevent leaking goroutines
		defer probeMap.Clean(key)
		if err := progLoader.Load(nestedCtx, loaderOpts); err != nil && !errors.Is(err, context.Canceled) {
			contextutils.LoggerFrom(nestedCtx).Errorf("could not load BPF program: %v", err)
		}
	}()

	return nil
}

func getProgram(
	ctx context.Context,
	progLocation, cacheDir string,
) (io.ReaderAt, error) {
	client := spec.NewEbpfOCICLient()
	prog, err := spec.TryFromLocal(
		ctx,
		progLocation,
		cacheDir,
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
