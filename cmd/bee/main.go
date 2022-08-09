package main

import (
	"log"

	"github.com/solo-io/bumblebee/pkg/cli"
	"oras.land/oras-go/pkg/context"
)

func main() {
	// Use context with discarded logrus logger so we don't fill our logs unecessarily
	ctx := context.Background()
	if err := cli.Bee().ExecuteContext(ctx); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}
