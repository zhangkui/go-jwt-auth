#!/bin/bash
set -e

IMAGE_NAME="${1:-go-project}"
PLATFORM="${2:-linux/amd64}"

echo "Building Docker image: $IMAGE_NAME for $PLATFORM"

docker build --platform "$PLATFORM" -t "$IMAGE_NAME:latest" -f benzhi.Dockerfile .

echo "Build complete: $IMAGE_NAME:latest ($PLATFORM)"
echo "Run with: docker run -it $IMAGE_NAME:latest"