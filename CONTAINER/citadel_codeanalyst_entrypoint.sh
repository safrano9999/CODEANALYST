#!/usr/bin/env bash
set -euo pipefail
TS_SOCKET="${TS_SOCKET:-/var/run/tailscale/tailscaled.sock}"
TS_STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
TS_STATE="${TS_STATE:-${TS_STATE_DIR}/tailscaled.state}"
TS_CERT_DIR="${TS_CERT_DIR:-${TS_STATE_DIR}/certs}"
CADDY_TEMPLATE="${CADDY_TEMPLATE:-/opt/CITADEL/deploy/Caddyfile}"
CADDY_CONFIG="${CADDY_CONFIG:-/etc/caddy/Caddyfile}"
LOCAL_CERT_DIR="${LOCAL_CERT_DIR:-/opt/CITADEL/certs}"
mkdir -p /var/run/tailscale "${TS_STATE_DIR}" "${TS_CERT_DIR}" "${LOCAL_CERT_DIR}" /run/php-fpm
echo "[app] starting tailscaled ..."
tailscaled --state="${TS_STATE}" --socket="${TS_SOCKET}" ${TS_TAILSCALED_EXTRA_ARGS:---tun=userspace-networking} &
for _ in $(seq 1 120); do
  [[ -S "${TS_SOCKET}" ]] && break
  sleep 1
done
if [[ ! -S "${TS_SOCKET}" ]]; then
  echo "[app] tailscaled socket not ready; abort"
  exit 1
fi
TS_UP_ARGS=()
if [[ -n "${TS_AUTHKEY:-}" ]]; then
  TS_UP_ARGS+=(--authkey="${TS_AUTHKEY}")
fi
if [[ -n "${TS_HOSTNAME:-}" ]]; then
  TS_UP_ARGS+=(--hostname="${TS_HOSTNAME}")
fi
tailscale --socket="${TS_SOCKET}" up "${TS_UP_ARGS[@]}" || true
for _ in $(seq 1 600); do
  state="$(tailscale --socket="${TS_SOCKET}" status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState", ""))' 2>/dev/null || true)"
  if [[ "${state}" == "Running" ]]; then
    break
  fi
  sleep "${TS_AUTH_POLL_INTERVAL:-2}"
done
TS_DOMAIN="$(tailscale --socket="${TS_SOCKET}" status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Self",{}).get("DNSName","").rstrip("."))' 2>/dev/null || true)"
if [[ -n "${TS_DOMAIN}" ]] && [[ -f "${CADDY_TEMPLATE}" ]]; then
  echo "[app] fetching tailscale TLS cert ..."
  tailscale --socket="${TS_SOCKET}" cert --cert-file="${TS_CERT_DIR}/cert.pem" --key-file="${TS_CERT_DIR}/key.pem" "${TS_DOMAIN}" || true
  sed "s|{TS_DOMAIN}|${TS_DOMAIN}|g" "${CADDY_TEMPLATE}" > "${CADDY_CONFIG}"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes -keyout "${LOCAL_CERT_DIR}/local-key.pem" -out "${LOCAL_CERT_DIR}/local.pem" -subj "/CN=citadel" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null || true
  php-fpm --daemonize || php-fpm -D || true
  caddy start --config "${CADDY_CONFIG}" || true
fi
if [ -x /opt/CITADEL/scan.sh ]; then
  (cd /opt/CITADEL && ./scan.sh || true)
fi
exec /bin/bash -lc 'cd /opt/CODEANALYST && python3 app.py'
