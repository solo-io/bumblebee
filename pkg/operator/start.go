package operator

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/rlimit"
	probes_bumblebee_io_v1alpha1 "github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1"
	"github.com/solo-io/bumblebee/pkg/api/probes.bumblebee.io/v1alpha1/controller"
	"github.com/solo-io/skv2/pkg/reconcile"
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

	mgr, err := manager.New(cfg, manager.Options{})
	if err != nil {
		return err
	}

	loop := controller.NewProbeReconcileLoop("bumblebee-operator", mgr, reconcile.Options{})

	return loop.RunProbeReconciler(ctx, &probeReconciler{ctx}, &predicate.GenerationChangedPredicate{})
}

type probeReconciler struct {
	ctx context.Context
}

// This function will be triggered when a new probe is created, or the gerneration of a probe is changed.
func (r *probeReconciler) ReconcileProbe(obj *probes_bumblebee_io_v1alpha1.Probe) (reconcile.Result, error) {
	return reconcile.Result{}, nil
}

// This function will be triggered when a probe is deleted.
func (p *probeReconciler) ReconcileProbeDeletion(req reconcile.Request) error {
	return nil
}
