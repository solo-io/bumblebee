package operator

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/bumblebee/pkg/stats"
	"github.com/solo-io/go-utils/contextutils"
	"github.com/solo-io/skv2/pkg/reconcile"
	reconcile_v2 "github.com/solo-io/skv2/pkg/reconcile/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"oras.land/oras-go/pkg/content"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func Start(ctx context.Context) error {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit (check for sudo or setcap): %v", err)
	}

	cfg, err := config.GetConfig()
	if err != nil {
		return err
	}

	if err := probes_bumblebee_io_v1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	mgr, err := manager.New(cfg, manager.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}

	ap := &atomic.Pointer[map[string]string]{}

	nodeLabels := map[string]string{}
	nodeName, ok := os.LookupEnv("NODE_NAME")
	if ok {
		// TODO: But a watch on the node to update the nodeLabels live.
		node := corev1.Node{}
		if err := mgr.GetClient().Get(ctx, types.NamespacedName{
			Name: nodeName,
		}, &node); err != nil {
			return err
		}
		nodeLabels = node.GetLabels()

		nodeLoop := reconcile_v2.NewLoop("node-watcher", mgr, &corev1.Node{}, reconcile_v2.Options{})

		if err := nodeLoop.RunReconciler(ctx,
			&reconcile_v2.ReconcileFuncs[*corev1.Node]{
				ReconcileFunc: func(ctx context.Context, obj *corev1.Node) (reconcile.Result, error) {
					// Update stored labels
					ap.Store(&obj.Labels)
					return reconcile.Result{}, nil
				},
			},
			predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					return e.ObjectNew.GetName() == nodeName
				},
			},
		); err != nil {
			return err
		}
	}

	promProvider, err := stats.NewPrometheusMetricsProvider(ctx, &stats.PrometheusOpts{})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)

	ap.Store(&nodeLabels)

	probeLoop := reconcile_v2.NewLoop("bumblebee-operator", mgr, &probes_bumblebee_io_v1alpha1.Probe{}, reconcile_v2.Options{})
	if err := probeLoop.RunReconciler(ctx, &probeReconciler{
		progLoader: progLoader,
		rps:        &runningProbes{probes: &sync.Map{}},
		nodeLabels: &atomic.Pointer[map[string]string]{},
	}, &predicate.GenerationChangedPredicate{}); err != nil {
		return err
	}

	return mgr.Start(ctx)
}

type probeReconciler struct {
	// TODO: Account for image name changes
	rps        *runningProbes
	progLoader loader.Loader
	// Labels on the node the current pod is running on.
	nodeLabels *atomic.Pointer[map[string]string]
}

// This function will be triggered when a new probe is created, or the gerneration of a probe is changed.
func (r *probeReconciler) Reconcile(ctx context.Context, obj *probes_bumblebee_io_v1alpha1.Probe) (reconcile.Result, error) {
	key := types.NamespacedName{
		Name:      obj.Name,
		Namespace: obj.Namespace,
	}
	selectionSet := labels.SelectorFromSet(labels.Set(obj.Spec.GetNodeSelector()))
	if !selectionSet.Matches(labels.Set(*(r.nodeLabels.Load()))) {
		return reconcile.Result{}, nil
	}

	currentImg, ok := r.rps.ImageName(key)
	if ok {
		if currentImg == obj.Spec.GetImageName() {
			// Image is already running :)
			return reconcile.Result{}, nil
		}
		// Image is already running, but with a different image.
		// Cancel the running program and start the new one.
		r.rps.Clean(key)
	}
	if err := r.startProgram(ctx, obj); err != nil {
		fmt.Errorf("uh oh %v", err)
		return reconcile.Result{}, nil
	}
	return reconcile.Result{}, nil
}

// This function will be triggered when a probe is deleted.
func (p *probeReconciler) ReconcileDeletion(ctx context.Context, req reconcile.Request) error {

	// Cancel the running program if found
	p.rps.Clean(req.NamespacedName)
	return nil
}

func (p *probeReconciler) startProgram(ctx context.Context, obj *probes_bumblebee_io_v1alpha1.Probe) error {

	rd, err := getProgram(ctx, obj.Spec.GetImageName())
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

	p.rps.Store(key, &runningProbe{
		image:  obj.Spec.GetImageName(),
		cancel: cancel,
	})
	go func() {
		// always cancel the context to prevent leaking goroutines
		defer p.rps.Clean(key)
		if err := p.progLoader.Load(nestedCtx, loaderOpts); err != nil && !errors.Is(err, context.Canceled) {
			contextutils.LoggerFrom(nestedCtx).Errorf("could not load BPF program: %v", err)
		}
	}()

	return nil
}

func getProgram(
	ctx context.Context,
	progLocation string,
) (io.ReaderAt, error) {
	client := spec.NewEbpfOCICLient()
	prog, err := spec.TryFromLocal(
		ctx,
		progLocation,
		"/tmp/image-cache",
		client,
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

type runningProbes struct {
	probes *sync.Map
}

func (r *runningProbes) Store(key types.NamespacedName, rp *runningProbe) {
	r.probes.Store(key, rp)
}

func (r *runningProbes) Clean(key types.NamespacedName) {
	val, ok := r.probes.LoadAndDelete(key)
	if !ok {
		return
	}
	rp := val.(*runningProbe)
	rp.cancel()
}

func (r *runningProbes) ImageName(key types.NamespacedName) (string, bool) {
	val, ok := r.probes.Load(key)
	if !ok {
		return "", false
	}
	return val.(*runningProbe).image, ok
}

type runningProbe struct {
	// TODO: use sha here instead of image name
	image  string
	cancel context.CancelFunc
}
