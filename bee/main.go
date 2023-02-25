package main

import (
	"fmt"
	"log"

	"github.com/solo-io/bumblebee/pkg/cli"
	"oras.land/oras-go/pkg/context"
)

func main() {
	fmt.Println("this is my special bee")
	// Use context with discarded logrus logger so we don't fill our logs unecessarily
	ctx := context.Background()
	if err := cli.Bee().ExecuteContext(ctx); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}
