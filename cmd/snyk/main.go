package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/denjamio/snyk-cli/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.NewOSStreams())
	stop()
	os.Exit(code)
}
