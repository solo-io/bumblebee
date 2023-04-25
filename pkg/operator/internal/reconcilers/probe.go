package reconcilers

import (
	"context"

	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/operator/internal/cache"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func NewProbeReconciler(
	pc cache.ProbeCache,
) *probeReconciler {
	return &probeReconciler{
		pc: pc,
	}
}

type probeReconciler struct {
	pc cache.ProbeCache
}

// This function will be triggered when a new probe is created, or the gerneration of a probe is changed.
func (r *probeReconciler) Reconcile(ctx context.Context, obj *probes_bumblebee_io_v1alpha1.Probe) (reconcile.Result, error) {
	key := types.NamespacedName{
		Name:      obj.Name,
		Namespace: obj.Namespace,
	}
	logger := contextutils.LoggerFrom(contextutils.WithLoggerValues(ctx, zap.String("probe_id", key.String())))
	logger.Debugf("handling probe create/update")
	if err := r.pc.UpdateProbe(ctx, obj); err != nil {
		// FIXME retry?
		logger.Error(err)
		return reconcile.Result{}, nil
	}
	return reconcile.Result{}, nil
}

// This function will be triggered when a probe is deleted.
func (p *probeReconciler) ReconcileDeletion(ctx context.Context, req reconcile.Request) error {
	logger := contextutils.LoggerFrom(contextutils.WithLoggerValues(ctx, zap.String("probe_id", req.NamespacedName.String())))
	logger.Debugf("handling deletion of probe")
	// Cancel the running program if found
	p.pc.Clean(req.NamespacedName)
	return nil
}
