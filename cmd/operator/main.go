package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/zapr"
	"github.com/solo-io/bumblebee/pkg/operator"
	"github.com/solo-io/go-utils/contextutils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/klog/v2"
	ctrl_log "sigs.k8s.io/controller-runtime/pkg/log"
)

func main() {
	if err := cmd().ExecuteContext(context.Background()); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}

func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := buildContext(cmd.Context(), false)
			if err != nil {
				return err
			}
			return operator.Start(ctx)
		},
	}
	return cmd
}

func buildContext(ctx context.Context, debug bool) (context.Context, error) {
	ctx, cancel := context.WithCancel(ctx)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		fmt.Println("got sigterm or interrupt")
		cancel()
	}()
	cfg := zap.NewDevelopmentConfig()
	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("couldn't create zap logger: '%w'", err)
	}

	// controller-runtime
	zapLogger := zapr.NewLogger(logger)
	ctrl_log.SetLogger(zapLogger)
	klog.SetLogger(zapLogger)

	contextutils.SetFallbackLogger(logger.Sugar())

	return ctx, nil
}
