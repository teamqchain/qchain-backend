#!/usr/bin/env bash
# Build the QChain gateway image: Nginx in front of the Go API (see nginx.conf).
# QPortal is no longer built here; it is hosted on Vercel and the gateway's
# root (/) redirects to it.
#
# Usage: bash gateway/docker-build.sh   (from anywhere; build context = gateway/)
#
# The image keeps its original name, qchain-web-gateway, so the CI deploy's
# rollback point (qchain-web-gateway:previous) keeps working.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="qchain-web-gateway:latest"

echo "=== Building $IMAGE ==="
echo "    Context : $SCRIPT_DIR"
echo ""

docker build -t "$IMAGE" "$SCRIPT_DIR"

echo ""
echo "=== Build complete ==="
echo "Image : $IMAGE"
echo "Run   : bash gateway/docker-run.sh"
