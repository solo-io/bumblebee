package operator

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1/controller"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/spec"
	"github.com/solo-io/bumblebee/pkg/stats"
	"github.com/solo-io/skv2/pkg/reconcile"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"oras.land/oras-go/pkg/content"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
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

	promProvider, err := stats.NewPrometheusMetricsProvider(ctx, &stats.PrometheusOpts{})
	if err != nil {
		return err
	}

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)

	loop := controller.NewProbeReconcileLoop("bumblebee-operator", mgr, reconcile.Options{})
	if err := loop.RunProbeReconciler(ctx, &probeReconciler{
		ctx:        ctx,
		progLoader: progLoader,
	}, &predicate.GenerationChangedPredicate{}); err != nil {
		return err
	}

	return mgr.Start(ctx)
}

type probeReconciler struct {
	ctx context.Context
	// TODO: Account for image name changes
	running    map[types.NamespacedName]context.CancelFunc
	progLoader loader.Loader
}

// This function will be triggered when a new probe is created, or the gerneration of a probe is changed.
func (r *probeReconciler) ReconcileProbe(obj *probes_bumblebee_io_v1alpha1.Probe) (reconcile.Result, error) {
	key := types.NamespacedName{
		Name:      obj.Name,
		Namespace: obj.Namespace,
	}
	if _, ok := r.running[key]; ok {
		// Image is already running :)
		return reconcile.Result{}, nil
	}
	if err := r.startProgram(r.ctx, obj); err != nil {
		fmt.Errorf("uh oh %v", err)
		return reconcile.Result{}, nil
	}
	return reconcile.Result{}, nil
}

// This function will be triggered when a probe is deleted.
func (p *probeReconciler) ReconcileProbeDeletion(req reconcile.Request) error {

	// Cancel the running program if found
	if cancel, ok := p.running[req.NamespacedName]; ok {
		cancel()
	}
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
	}

	nestedCtx, cancel := context.WithCancel(ctx)
	if err := p.progLoader.Load(nestedCtx, loaderOpts); err != nil {
		// always cancel the context to prevent leaking goroutines
		cancel()
		return err
	}

	p.running[types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}] = cancel
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
