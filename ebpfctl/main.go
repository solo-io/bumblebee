package main

import (
	"context"
	"log"

	"github.com/solo-io/gloobpf/pkg/cli"
)

func main() {
	ctx := context.Background()
	if err := cli.EbpfCtl().ExecuteContext(ctx); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}
