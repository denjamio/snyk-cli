#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${GO_IMAGE:-golang:1.25-bookworm}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
mkdir -p bin
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e GOCACHE=/tmp/go-build-cache \
  -e GOPATH=/tmp/go-path \
  -e VERSION="$VERSION" \
  -v "$PWD":/app \
  -w /app \
  "$IMAGE" \
  go build -trimpath -ldflags "-s -w -X github.com/denjamio/snyk-cli/internal/cli.Version=$VERSION" \
  -o bin/snyk ./cmd/snyk
