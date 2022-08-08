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
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const ImageCache = "/tmp/image-cache"

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

	nodeName, ok := os.LookupEnv("NODE_NAME")
	if !ok {
		// TODO: check for pod name
		return fmt.Errorf("NODE_NAME environment variable not set, it must be to know where we are running")
	}

	cli, err := v1.NewForConfig(cfg)
	if err != nil {
		return err
	}
	node, err := cli.Nodes().Get(ctx, nodeName, metav1.GetOptions{})
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

	probeCache := cache.NewProbeCache(ImageCache, node.GetLabels(), progLoader)

	nodeLoop := reconcile_v2.NewLoop("node-watcher", mgr, &corev1.Node{}, reconcile_v2.Options{})
	if err := nodeLoop.RunReconciler(ctx,
		reconcilers.NewNodeReconciler(probeCache),
		// Only run if it's our node
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

	probeLoop := reconcile_v2.NewLoop("probe-watcher", mgr, &probes_bumblebee_io_v1alpha1.Probe{}, reconcile_v2.Options{})
	if err := probeLoop.RunReconciler(ctx, reconcilers.NewProbeReconciler(probeCache), &predicate.GenerationChangedPredicate{}); err != nil {
		return err
	}

	return mgr.Start(ctx)
}
