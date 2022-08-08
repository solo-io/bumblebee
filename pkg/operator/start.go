package operator

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"github.com/solo-io/bumblebee/pkg/loader"
	"github.com/solo-io/bumblebee/pkg/operator/internal/cache"
	"github.com/solo-io/bumblebee/pkg/operator/internal/reconcilers"
	"github.com/solo-io/bumblebee/pkg/stats"
	reconcile_v2 "github.com/solo-io/skv2/pkg/reconcile/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	corev1_clients "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const ImageCache = "/tmp/image-cache"

// TODO:
// 1. Use our stats server and add all stats to that. Controller runtime and our app.
// 2. Cosign verification for the images.
// 3. Authentication for the images.
func Start(ctx context.Context) error {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("could not raise memory limit (check for sudo or setcap): %v", err)
	}

	cfg, err := config.GetConfig()
	if err != nil {
		return err
	}

	// Add our probe CRD to the scheme so it is known to the client.
	if err := probes_bumblebee_io_v1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	mgr, err := manager.New(cfg, manager.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		return err
	}

	nodeName, ok := os.LookupEnv("NODE_NAME")
	if !ok {
		// TODO: check for pod name, can get node from there.
		return fmt.Errorf("NODE_NAME environment variable not set, it must be to know where we are running")
	}

	cli, err := corev1_clients.NewForConfig(cfg)
	if err != nil {
		return err
	}
	node, err := cli.Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// The stats provider is a factory for creating prometheus collectors used
	// by the prog_loader
	promProvider := stats.NewPrometheusMetricsProvider(ctx, metrics.Registry)

	progLoader := loader.NewLoader(
		decoder.NewDecoderFactory(),
		promProvider,
	)
	/*
		The probe cache is the core of the application.
		It's main responsibility is to store the state of the probes on the node.
		It does this in 3 ways:
			1. Starting the probes when the CR is created.
			2. Removing the probes when the CR is deleted.
			3. Scheulding and unscheulding the probes when the node labels change.

		Each of the above pieces is captured by a reconciler.
		The first 2 by the probe recocniler, the last by the node reconciler.
	*/
	probeCache := cache.NewProbeCache(ImageCache, node.GetLabels(), progLoader)

	// Create and start the node reconciler
	nodeLoop := reconcile_v2.NewLoop("node-watcher", mgr, &corev1.Node{}, reconcile_v2.Options{})
	if err := nodeLoop.RunReconciler(ctx,
		reconcilers.NewNodeReconciler(probeCache),
		// Only run if it's our node AND the node's labels have changed.
		predicate.And(
			predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					return e.ObjectNew.GetName() == nodeName
				},
			},
			predicate.LabelChangedPredicate{},
		),
	); err != nil {
		return err
	}

	// Create and start the probe reconciler
	probeLoop := reconcile_v2.NewLoop("probe-watcher", mgr, &probes_bumblebee_io_v1alpha1.Probe{}, reconcile_v2.Options{})
	if err := probeLoop.RunReconciler(
		ctx,
		reconcilers.NewProbeReconciler(probeCache),
		predicate.GenerationChangedPredicate{},
	); err != nil {
		return err
	}

	// Start the manager, this is the main blocking call for the application.
	// All other goroutines are started by the manager. It's pretty useful tbh :laughing:
	return mgr.Start(ctx)
}