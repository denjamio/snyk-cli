#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${GO_IMAGE:-golang:1.25-bookworm}"
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e GOCACHE=/tmp/go-build-cache \
  -e GOPATH=/tmp/go-path \
  -v "$PWD":/app \
  -w /app \
  "$IMAGE" \
  sh -c '
    set -e
    unformatted="$(gofmt -l .)"
    if [ -n "$unformatted" ]; then
      echo "unformatted files:"
      echo "$unformatted"
      exit 1
    fi
    go vet ./...
    go test -race ./...
  '
