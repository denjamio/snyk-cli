package main

import (
	"os"

	"github.com/denjamio/snyk-cli/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.NewOSStreams()))
}
