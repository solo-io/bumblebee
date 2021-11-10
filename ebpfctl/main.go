package main

import (
	"log"

	"github.com/solo-io/gloobpf/pkg/cli"
	"oras.land/oras-go/pkg/context"
)

func main() {
	// Use context with discarded logrus logger so we don't fill our logs unecessarily
	ctx := context.Background()
	if err := cli.EbpfCtl().ExecuteContext(ctx); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}
