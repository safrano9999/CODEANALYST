#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/env.example" ]; then
    DIR="$SCRIPT_DIR"
else
    DIR="$(pwd)"
fi
ENV="$DIR/.env"
EXAMPLE="$DIR/env.example"
PROJECT_NAME="$(basename "$DIR")"
CONTAINER_NAME="${PROJECT_NAME,,}"

[ ! -f "$EXAMPLE" ] && echo "No env.example" && exit 1

echo ""
echo "  Configuring $PROJECT_NAME"
echo ""

touch "$ENV"
declare -A seen_keys=()

while IFS= read -r line <&3; do
    stripped="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$stripped" || "$stripped" == \#* ]] && continue

    entry="${line%%#*}"
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ "$entry" != *=* ]] && continue

    key="${entry%%=*}"
    default="${entry#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    default="${default#"${default%%[![:space:]]*}"}"
    default="${default%"${default##*[![:space:]]}"}"

    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -n "${seen_keys[$key]+x}" ]]; then
        echo "    duplicate $key in env.example" >&2
        continue
    fi
    seen_keys[$key]=1

    existing="$(grep "^${key}=" "$ENV" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    if [ -n "$existing" ]; then
        echo "    $key= exists"
        continue
    fi
    # Remove stale empty entry if present
    sed -i "/^${key}=$/d" "$ENV" 2>/dev/null || true

    if [ -n "$default" ]; then
        printf "    %s [%s]: " "$key" "$default"
    else
        printf "    %s: " "$key"
    fi
    read -r val || true
    if [ -z "$val" ]; then
        val="$default"
    fi

    if [ -z "$val" ]; then
        echo "    $key= skipped"
        continue
    fi
    echo "$key=$val" >> "$ENV"
done 3< "$EXAMPLE"

env_default() {
    local wanted="$1"
    while IFS= read -r line <&3; do
        stripped="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$stripped" || "$stripped" == \#* ]] && continue

        entry="${line%%#*}"
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ "$entry" != *=* ]] && continue

        key="${entry%%=*}"
        default="${entry#*=}"
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        default="${default#"${default%%[![:space:]]*}"}"
        default="${default%"${default##*[![:space:]]}"}"

        if [ "$key" = "$wanted" ]; then
            printf "%s\n" "$default"
            return 0
        fi
    done 3< "$EXAMPLE"
}

env_val() {
    local key="$1"
    local val
    val="$(grep "^${key}=" "$ENV" 2>/dev/null | head -1 | cut -d= -f2-)"
    if [ -n "$val" ]; then
        printf "%s\n" "$val"
        return 0
    fi
    env_default "$key"
}

env_port_key() {
    local fallback=""
    while IFS= read -r line <&3; do
        stripped="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$stripped" || "$stripped" == \#* ]] && continue

        entry="${line%%#*}"
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ "$entry" != *=* ]] && continue

        key="${entry%%=*}"
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue

        if [ "$key" = "PORT" ]; then
            printf "%s\n" "$key"
            return 0
        fi
        if [[ "$key" == *_PORT && -z "$fallback" ]]; then
            fallback="$key"
        fi
    done 3< "$EXAMPLE"

    [ -n "$fallback" ] && printf "%s\n" "$fallback"
}

project_host() {
    local host
    host="$(env_val HOST)"
    if [ -z "$host" ]; then
        echo "Error: HOST must be set in .env or env.example" >&2
        exit 1
    fi
    blocked_host="$(printf '%s.%s.%s.%s' 0 0 0 0)"
    if [ "$host" = "$blocked_host" ]; then
        echo "Error: HOST must use 127.0.0.1" >&2
        exit 1
    fi
    printf "%s\n" "$host"
}

project_port() {
    local key
    key="$(env_port_key)"
    if [ -z "$key" ]; then
        echo "Error: No PORT or *_PORT key configured in env.example" >&2
        exit 1
    fi

    local port
    port="$(env_val "$key")"
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "Error: $key must be set to a numeric port" >&2
        exit 1
    fi
    printf "%s\n" "$port"
}

_write_or_update() {
    local target_file="$1"
    local new_content="$2"
    local label="$3"

    if [ -f "$target_file" ]; then
        if echo "$new_content" | diff -q "$target_file" - >/dev/null 2>&1; then
            echo "  $target_file unchanged."
            return
        fi
        echo ""
        echo "  $target_file differs from new version:"
        diff --color=auto "$target_file" <(echo "$new_content") || true
        echo ""
        printf "  Replace with new %s? [y/n]: " "$label"
        read -r answer
        if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
            echo "  Keeping existing $target_file"
            return
        fi
    fi

    echo "$new_content" > "$target_file"
    echo "  Written: $target_file"
}

generate_quadlet() {
    local host="$1"
    local port="$2"
    local quadlet_file="$DIR/$CONTAINER_NAME.container"

    local content
    content="$(cat <<EOF
[Container]
ContainerName=$CONTAINER_NAME
Image=localhost/$CONTAINER_NAME
PublishPort=$port:$port
EnvironmentFile=$ENV
Exec=uvicorn webui:app --host $host --port $port
#AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF
)"

    _write_or_update "$quadlet_file" "$content" "quadlet"
}

generate_compose() {
    local host="$1"
    local port="$2"
    local compose_file="$DIR/docker-compose.yml"

    local content
    content="$(cat <<EOF
# docker-compose.yml — $PROJECT_NAME
# Usage: docker compose up -d

services:
  $CONTAINER_NAME:
    image: localhost/$CONTAINER_NAME
    container_name: $CONTAINER_NAME
    hostname: $CONTAINER_NAME
    ports:
      - "$port:$port"
    env_file:
      - $ENV
    command: uvicorn webui:app --host $host --port $port
    restart: always
EOF
)"

    _write_or_update "$compose_file" "$content" "docker-compose.yml"
}

HOST_VALUE="$(project_host)"
PORT_VALUE="$(project_port)"
generate_quadlet "$HOST_VALUE" "$PORT_VALUE"
generate_compose "$HOST_VALUE" "$PORT_VALUE"

echo ""
