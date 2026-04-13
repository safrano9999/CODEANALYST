#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="localhost/citadel-codeanalyst:latest"
CONTAINER_NAME="citadel-codeanalyst"
HOST_NAME="citadel-codeanalyst"
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
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/citadel_codeanalyst.env}"
INJECT_ENV_FILE="${INJECT_ENV_FILE:-${SCRIPT_DIR}/citadel_codeanalyst.inject.env}"
ENV_ARGS=()
if [[ -f "${ENV_FILE}" ]]; then
  ENV_ARGS+=(--env-file "${ENV_FILE}")
fi
if [[ -f "${INJECT_ENV_FILE}" ]]; then
  ENV_ARGS+=(--env-file "${INJECT_ENV_FILE}")
fi
"${ENGINE}" rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
CONTAINER_ID="$(${ENGINE} run -d --name "${CONTAINER_NAME}" --hostname "${HOST_NAME}" --network host "${ENV_ARGS[@]}" "${IMAGE_NAME}")"
echo "[info] started container: ${CONTAINER_ID}"
if [[ "${FOLLOW_LOGS:-1}" == "1" ]]; then
  "${ENGINE}" logs -f "${CONTAINER_NAME}" || true
fi
