#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="localhost/citadel-codeanalyst:latest"
BUILD_CONTEXT="/home/openclaw/saf"
ENGINE_DEFAULT="podman"
if command -v "${ENGINE_DEFAULT}" >/dev/null 2>&1; then
  ENGINE="${ENGINE_DEFAULT}"
elif command -v docker >/dev/null 2>&1; then
  ENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
else
  echo "[error] neither podman nor docker found in PATH" >&2
  exit 127
fi
"${ENGINE}" build -f "${SCRIPT_DIR}/citadel_codeanalyst.Dockerfile" -t "${IMAGE_NAME}" "${BUILD_CONTEXT}"
