#!/usr/bin/env bash
# Build the QChain API Docker image (qchain-api:latest).
# The build context is the repository root, because the image needs the Go
# packages there (main, api, config, db, ledger, pqc and cmd); the Dockerfile
# lives in docker/.
#
# Usage: bash docker/docker-build.sh   (from anywhere)
#
# First build takes ~20 min (liboqs compiles from source).
# Subsequent builds are cached and take ~2 min.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building qchain-api Docker image ==="
echo "    Context    : $REPO_ROOT"
echo "    Dockerfile : $SCRIPT_DIR/Dockerfile"
echo "    This takes ~20 min on first build (liboqs compilation)."
echo ""

docker build \
    --tag qchain-api:latest \
    -f "$SCRIPT_DIR/Dockerfile" \
    "$REPO_ROOT"

echo ""
echo "=== Build complete ==="
echo "Image: qchain-api:latest"
echo "Run  : bash docker/docker-run.sh"
