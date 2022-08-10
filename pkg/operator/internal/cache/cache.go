package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/go-utils/contextutils"
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

const ImageCache = "/tmp/image-cache"

// ProbeCache is a component responsible for keeping track of probe resources.
type ProbeCache interface {
	// UpdateNodeLabels takes in a list of node labels and compares them against
	// The cached probe node selector. If the node selector matches the
	// current node, and isn't yet running, start it. Likewise if it's
	// running but shouldn't be, cancel it.
	UpdateNodeLabels(ctx context.Context, nodeLabels map[string]string) error
	// UpdateProbe adds or updates a single probe's lifecycle status in the cache.
	// If the image name has changed from it's existing one, the old one will be
	// cancelled, and the new one started.
	UpdateProbe(ctx context.Context, probe *probes_bumblebee_io_v1alpha1.Probe) error
	// Clean removes a probe from the cache. It will stop the probe if it is running.
	Clean(key types.NamespacedName)
}

type PullFuncFactory func(pullPolicy probes_bumblebee_io_v1alpha1.ProbeSpec_PullPolicy) spec.PullFunc

var defaultPullFactory PullFuncFactory = func(pullPolicy probes_bumblebee_io_v1alpha1.ProbeSpec_PullPolicy) spec.PullFunc {
	switch pullPolicy {
	case probes_bumblebee_io_v1alpha1.ProbeSpec_Always:
		return spec.Pull
	case probes_bumblebee_io_v1alpha1.ProbeSpec_Never:
		return spec.NeverPull
	default:
		return spec.TryFromLocal
	}
}

type Options struct {
	CacheDir   string
	NodeLabels map[string]string
	ProgLoader loader.Loader
	Factory    PullFuncFactory
}

func (o *Options) initDefaults() {
	if o.CacheDir == "" {
		o.CacheDir = ImageCache
	}

	if o.Factory == nil {
		o.Factory = defaultPullFactory
	}
}

// NewProbeCache creates a new probe cache.
func NewProbeCache(
	opts Options,
) *probeCache {
	opts.initDefaults()
	ap := &atomic.Pointer[map[string]string]{}
	ap.Store(&opts.NodeLabels)
	return &probeCache{
		probes:     &atomicProbeMap{probes: &sync.Map{}},
		nodeLabels: ap,
		progLoader: opts.ProgLoader,
		cacheDir:   opts.CacheDir,
		factory:    opts.Factory,
	}
}

type probeCache struct {
	cacheDir   string
	probes     *atomicProbeMap
	nodeLabels *atomic.Pointer[map[string]string]
	progLoader loader.Loader
	factory    PullFuncFactory
}

func (r *probeCache) UpdateNodeLabels(ctx context.Context, nodeLabels map[string]string) error {
	r.nodeLabels.Store(&nodeLabels)
	var multierr *multierror.Error
	r.probes.Range(func(key types.NamespacedName, probe *cachedProbe) bool {
		// If the probe node selector matches the current node, and isn't yet running, start it.
		if labels.SelectorFromSet(probe.probe.Spec.NodeSelector).Matches(labels.Set(nodeLabels)) && !probe.running {
			if err := startProgram(ctx, probe.probe, r.progLoader, r.probes, r.cacheDir, r.factory); err != nil {
				multierr = multierror.Append(err)
			}
			// Continue iteration
			return true
		}

		// If the node selector matches the current node, and is running, cancel it.
		if !labels.SelectorFromSet(probe.probe.Spec.NodeSelector).Matches(labels.Set(nodeLabels)) && probe.running {
			probe.Stop()
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
	if probe, ok := r.probes.Probe(key); ok {
		contextutils.LoggerFrom(ctx).Debug("Restarting probe as the generation has changed")
		probe.Stop()
		// Attempt to restart program, if it fails, return error.
	}
	// Check if the node selcetor matches the node labels
	if labels.SelectorFromSet(probe.Spec.NodeSelector).Matches(labels.Set(currentLabels)) {
		// If so attempt to start the program
		contextutils.LoggerFrom(ctx).Debug("Attempting to start program")
		if err := startProgram(ctx, probe, r.progLoader, r.probes, r.cacheDir, r.factory); err != nil {
			return err
		}
	} else {
		contextutils.LoggerFrom(ctx).Debug("Node selector doesn't match current node, not starting program")
	}

	return nil
}

func (p *probeCache) Clean(key types.NamespacedName) {
	p.probes.Clean(key)
}

// FIXME: make this output JSON so it's consumbale via API
func (p *probeCache) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	builder := strings.Builder{}
	p.probes.Range(func(key types.NamespacedName, probe *cachedProbe) bool {
		builder.WriteString(fmt.Sprintf("resource: (%s), running: (%t)\n", key.String(), probe.running))
		return true
	})
	w.Write([]byte(builder.String()))
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

func (c *cachedProbe) Stop() {
	if !c.running {
		return
	}
	c.cancel()
	c.cancel = nil
	c.running = false
}

func startProgram(
	ctx context.Context,
	obj *probes_bumblebee_io_v1alpha1.Probe,
	progLoader loader.Loader,
	probeMap *atomicProbeMap,
	cacheDir string,
	factory PullFuncFactory,
) error {

	rd, err := getProgram(ctx, obj.Spec.GetImagePullPolicy(), obj.Spec.GetImage(), cacheDir, factory)
	if err != nil {
		return err
	}
	parsedELF, err := progLoader.Parse(ctx, rd)
	if err != nil {
		return fmt.Errorf("could not parse BPF program: %w", err)
	}

	additionalLabels := map[string]string{
		"probe_name":      obj.Name,
		"probe_namespace": obj.Namespace,
	}
	if len(obj.Spec.GetAdditionalLabels()) > 0 {
		maps.Copy(additionalLabels, obj.Spec.GetAdditionalLabels())
	}

	loaderOpts := &loader.LoadOptions{
		ParsedELF: parsedELF,
		Watcher:   loader.NewNoopWatcher(),
	}

	watchOpts, err := progLoader.Load(ctx, loaderOpts)
	if err != nil {
		return err
	}
	watchOpts.AdditionalLabels = additionalLabels

	key := types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}

	nestedCtx, cancel := context.WithCancel(ctx)

	probe := &cachedProbe{
		probe:   obj.DeepCopy(),
		cancel:  cancel,
		running: true,
	}
	probeMap.Store(key, probe)
	go func() {
		contextutils.LoggerFrom(nestedCtx).Debug("Starting program")
		// always cancel the context to prevent leaking goroutines
		defer probe.Stop()
		if err := progLoader.WatchMaps(nestedCtx, watchOpts); err != nil && !errors.Is(err, context.Canceled) {
			contextutils.LoggerFrom(nestedCtx).Errorf("error runnign BPF program: %v", err)
		}
	}()

	return nil
}

func getProgram(
	ctx context.Context,
	pullPolicy probes_bumblebee_io_v1alpha1.ProbeSpec_PullPolicy,
	progLocation, cacheDir string,
	factory PullFuncFactory,
) (io.ReaderAt, error) {
	client := spec.NewEbpfOCICLient()
	prog, err := factory(pullPolicy)(ctx, spec.PullOpts{
		Ref:             progLocation,
		LocalStorageDir: cacheDir,
		Client:          client,
	})
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
