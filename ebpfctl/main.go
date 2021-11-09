package main

import (
	"context"
	"log"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/solo-io/gloobpf/pkg/cli"
)

func main() {
	ctx := context.Background()
	// This is stderr by default for some reason
	logrus.SetOutput(os.Stdout)
	// Make oras quiet
	logrus.SetLevel(logrus.ErrorLevel)
	if err := cli.EbpfCtl().ExecuteContext(ctx); err != nil {
		log.Fatalf("exiting: %s", err)
	}
}
