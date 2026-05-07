#!/bin/bash
set -euo pipefail

# ── CODEANALYST Installer ───────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="CODEANALYST"
CONTAINER_NAME="codeanalyst"
IMAGE="safrano9999/python-fastapi:3.13"

echo ""
echo "  Project: $PROJECT_NAME"
echo "  Dir:     $PROJECT_DIR"
echo ""

# ── Requirements check ───────────────────────────────────────────────
if [ ! -f "$PROJECT_DIR/requirements.txt" ]; then
    echo "Error: No requirements.txt found in $PROJECT_DIR"
    exit 1
fi

# ── Detect available tools ───────────────────────────────────────────
HAS_PIP=false
HAS_UV=false
HAS_VENV=false
HAS_PODMAN=false
HAS_DOCKER=false

command -v pip  >/dev/null 2>&1 && HAS_PIP=true
command -v pip3 >/dev/null 2>&1 && HAS_PIP=true
command -v uv   >/dev/null 2>&1 && HAS_UV=true
python3 -m venv --help >/dev/null 2>&1 && HAS_VENV=true
command -v podman >/dev/null 2>&1 && HAS_PODMAN=true

# Check for real Docker (not podman wrapper)
if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION="$(docker --version 2>&1 || true)"
    if [[ "$DOCKER_VERSION" != *"podman"* ]]; then
        HAS_DOCKER=true
    fi
fi

# ── Build menu ───────────────────────────────────────────────────────
OPTIONS=()
LABELS=()

if $HAS_PIP; then
    OPTIONS+=("pip")
    LABELS+=("pip        — pip install directly")
fi
if $HAS_VENV; then
    OPTIONS+=("venv")
    LABELS+=("venv       — create venv + pip install")
fi
if $HAS_UV; then
    OPTIONS+=("uv")
    LABELS+=("uv         — uv pip install directly")
fi
if $HAS_PODMAN; then
    OPTIONS+=("podman")
    LABELS+=("podman     — container install (uv)")
fi
if $HAS_DOCKER; then
    OPTIONS+=("docker")
    LABELS+=("docker     — container install (uv)")
fi

if [ ${#OPTIONS[@]} -eq 0 ]; then
    echo "Error: No install method available."
    echo "Install at least one of: pip, uv, python3-venv, podman, or docker."
    exit 1
fi

echo "  Available install methods:"
echo ""
for i in "${!OPTIONS[@]}"; do
    echo "    $((i + 1))) ${LABELS[$i]}"
done
echo "    0) cancel"
echo ""
printf "  Choose [0-%d]: " "${#OPTIONS[@]}"
read -r CHOICE

if [ "$CHOICE" = "0" ] || [ -z "$CHOICE" ]; then
    echo "  Cancelled."
    exit 0
fi

INDEX=$((CHOICE - 1))
if [ "$INDEX" -lt 0 ] || [ "$INDEX" -ge "${#OPTIONS[@]}" ]; then
    echo "  Invalid choice."
    exit 1
fi

METHOD="${OPTIONS[$INDEX]}"
echo ""
echo "  Installing with: $METHOD"
echo ""

# ── Setup vars from .env.example ─────────────────────────────────────
prompt_setup_vars() {
    local ENV_FILE="$PROJECT_DIR/.env"
    local ENV_EXAMPLE="$PROJECT_DIR/.env.example"

    if [ ! -f "$ENV_EXAMPLE" ]; then
        return
    fi

    echo "  Configuring environment variables..."
    echo ""

    local ALL_VARS=""

    while IFS= read -r line; do
        stripped="$(echo "$line" | sed 's/^[[:space:]]*//')"
        if [ -z "$stripped" ] || [[ "$stripped" == \#* && "$stripped" != *"# ASK"* ]]; then
            ALL_VARS+="$line"$'\n'
            continue
        fi

        if [[ "$line" == *"# ASK"* ]]; then
            local key_part="${line%%# ASK*}"
            key_part="$(echo "$key_part" | sed 's/[[:space:]]*$//')"
            local key="${key_part%%=*}"
            local default="${key_part#*=}"
            default="$(echo "$default" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"

            if [ -n "$default" ]; then
                printf "    %s [%s]: " "$key" "$default"
            else
                printf "    %s: " "$key"
            fi
            read -r value
            if [ -z "$value" ]; then
                value="$default"
            fi
            ALL_VARS+="$key=$value"$'\n'
        else
            ALL_VARS+="$line"$'\n'
        fi
    done < "$ENV_EXAMPLE"

    printf "%s" "$ALL_VARS" > "$ENV_FILE"
    echo ""
    echo "  Written to $ENV_FILE"
}

# ── Show packages ────────────────────────────────────────────────────
show_deps() {
    echo "  Packages to install from requirements.txt:"
    echo ""
    while IFS= read -r line; do
        pkg="$(echo "$line" | sed 's/[>=<].*//' | sed 's/\[.*\]//' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"
        if [ -n "$pkg" ] && [[ "$pkg" != \#* ]]; then
            echo "    - $pkg"
        fi
    done < "$PROJECT_DIR/requirements.txt"
    echo ""
}

# ── Baremetal installs ───────────────────────────────────────────────
install_pip() {
    show_deps
    pip install -r "$PROJECT_DIR/requirements.txt"
    prompt_setup_vars
}

install_venv() {
    show_deps
    if [ ! -d "$PROJECT_DIR/venv" ]; then
        echo "  Creating venv..."
        python3 -m venv "$PROJECT_DIR/venv"
    fi
    "$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
    prompt_setup_vars
}

install_uv() {
    show_deps
    uv pip install -r "$PROJECT_DIR/requirements.txt"
    prompt_setup_vars
}

# ── Container install ────────────────────────────────────────────────
install_container() {
    local RUNTIME="$1"

    if $RUNTIME image exists "docker.io/$IMAGE" 2>/dev/null || $RUNTIME inspect "docker.io/$IMAGE" >/dev/null 2>&1; then
        echo "  Image found locally: $IMAGE"
        printf "  Skip or pull new? [s/n]: "
        read -r IMG_CHOICE
        if [ "$IMG_CHOICE" = "n" ] || [ "$IMG_CHOICE" = "N" ]; then
            echo "  Pulling latest $IMAGE..."
            $RUNTIME pull "docker.io/$IMAGE"
        else
            echo "  Skipping pull."
        fi
    else
        echo "  Pulling image $IMAGE..."
        $RUNTIME pull "docker.io/$IMAGE" 2>/dev/null || $RUNTIME pull "$IMAGE"
    fi

    # Build project image
    echo "  Building project image: $CONTAINER_NAME..."
    local CFILE="$PROJECT_DIR/Containerfile"
    cat > "$CFILE" <<DOCKERFILE
FROM docker.io/$IMAGE
WORKDIR /app
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt
COPY . .
CMD ["uvicorn", "webui:app", "--host", "0.0.0.0", "--port", "80"]
DOCKERFILE
    $RUNTIME build -t "$CONTAINER_NAME" -f "$CFILE" "$PROJECT_DIR"
    echo "  Image built: $CONTAINER_NAME"

    prompt_setup_vars

    # Generate quadlet + compose
    generate_quadlet
    generate_compose

    echo ""
    echo "  Run:  $RUNTIME run --rm -d --name $CONTAINER_NAME $CONTAINER_NAME"
    echo "  Or:   docker compose up -d"
}

# ── Generate Podman Quadlet ──────────────────────────────────────────
generate_quadlet() {
    local QUADLET_FILE="$PROJECT_DIR/$CONTAINER_NAME.container"
    local ENV_LINE=""

    if [ -f "$PROJECT_DIR/.env" ]; then
        ENV_LINE="EnvironmentFile=$PROJECT_DIR/.env"
    fi

    cat > "$QUADLET_FILE" <<EOF
[Container]
ContainerName=$CONTAINER_NAME
Image=localhost/$CONTAINER_NAME
PublishPort=80:80
#Network=host
${ENV_LINE}
Exec=uvicorn webui:app --host 0.0.0.0 --port 80
#AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
EOF

    echo ""
    echo "  Generated: $QUADLET_FILE"
}

# ── Generate docker-compose.yml ──────────────────────────────────────
generate_compose() {
    local COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
    local ENV_LINE=""

    if [ -f "$PROJECT_DIR/.env" ]; then
        ENV_LINE=$'\n    env_file:\n      - .env'
    fi

    cat > "$COMPOSE_FILE" <<EOF
# docker-compose.yml — $PROJECT_NAME
# Usage: docker compose up -d

services:
  $CONTAINER_NAME:
    image: localhost/$CONTAINER_NAME
    container_name: $CONTAINER_NAME
    hostname: $CONTAINER_NAME
    ports:
      - "80:80"
    #network_mode: host${ENV_LINE}
    command: uvicorn webui:app --host 0.0.0.0 --port 80
    restart: always
    #labels:
    #  - "com.centurylinklabs.watchtower.enable=true"
EOF

    echo "  Generated: $COMPOSE_FILE"
}

# ── Run ──────────────────────────────────────────────────────────────
case "$METHOD" in
    pip)    install_pip ;;
    venv)   install_venv ;;
    uv)     install_uv ;;
    podman) install_container podman ;;
    docker) install_container docker ;;
esac

echo ""
echo "  Done."
