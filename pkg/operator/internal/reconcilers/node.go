package reconcilers

import (
	"context"

	"github.com/solo-io/bumblebee/pkg/operator/internal/cache"
	"github.com/solo-io/go-utils/contextutils"
	reconcile_v2 "github.com/solo-io/skv2/pkg/reconcile/v2"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func NewNodeReconciler(
	pc cache.ProbeCache,
) reconcile_v2.Reconciler[*corev1.Node] {
	return &nodeReconciler{
		pc: pc,
	}
}

type nodeReconciler struct {
	pc cache.ProbeCache
}

func (r *nodeReconciler) Reconcile(ctx context.Context, obj *corev1.Node) (reconcile.Result, error) {
	logger := contextutils.LoggerFrom(contextutils.WithLoggerValues(ctx, zap.String("node_name", obj.Name)))
	logger.Debugf("handling change in node labels")
	// Update stored labels
	if err := r.pc.UpdateNodeLabels(ctx, obj.Labels); err != nil {
		// FIXME: retry?
		logger.Error(err)
	}
	return reconcile.Result{}, nil
}
