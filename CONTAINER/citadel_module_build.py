#!/usr/bin/env python3
"""Standardized per-repo builder: CITADEL base + module runtime + optional 3rd-party payload."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


DEFAULT_CITADEL_REPO = "https://github.com/safrano9999/CITADEL.git"
THIRDPARTY_NAMES = ["codex-cli", "openclaw", "hermes", "claude-code"]


@dataclass
class RuntimeProgram:
    name: str
    command: str
    directory: str
    autostart: bool = True
    autorestart: bool = True
    startsecs: int = 3
    priority: int = 200


@dataclass
class ThirdPartyDirective:
    name: str
    description: str
    default_selected: bool
    directory: Path


def run(cmd: list[str], *, cwd: Path | None = None, dry_run: bool = False) -> None:
    where = str(cwd) if cwd else str(Path.cwd())
    print(f"[run] ({where}) {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def ask_yes_no(question: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{question} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "j", "ja", "1", "true"}


def choose_engine(requested: str) -> str:
    if requested in {"podman", "docker"}:
        return requested
    for candidate in ("podman", "docker"):
        if subprocess.run(["bash", "-lc", f"command -v {candidate} >/dev/null 2>&1"]).returncode == 0:
            return candidate
    raise RuntimeError("No container engine found (podman/docker).")


def sanitize_tag_fragment(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value).strip("-._")
    return value or "module"


def sanitize_program_name(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value).strip("_")
    return value or "program"


def parse_module(module_file: Path, fallback_repo_name: str) -> tuple[str, str]:
    data = tomllib.loads(module_file.read_text())
    module = data.get("module", {}) if isinstance(data, dict) else {}

    module_name = str(module.get("name", "")).strip() or fallback_repo_name.lower()
    target_dir = str(module.get("target_dir", "")).strip() or fallback_repo_name
    return module_name, target_dir


def parse_runtime_programs(runtime_file: Path, *, module_name: str, target_dir: str) -> list[RuntimeProgram]:
    if not runtime_file.exists():
        return []

    data = tomllib.loads(runtime_file.read_text())
    runtime = data.get("runtime", data) if isinstance(data, dict) else {}
    if not isinstance(runtime, dict):
        return []

    programs: list[RuntimeProgram] = []
    raw_programs = runtime.get("programs", [])

    if isinstance(raw_programs, list):
        for idx, item in enumerate(raw_programs, start=1):
            if not isinstance(item, dict):
                continue
            command = str(item.get("command", "")).strip()
            if not command:
                continue
            name = sanitize_program_name(str(item.get("name", "")).strip() or f"{module_name}_{idx}")
            directory = str(item.get("directory", "")).strip() or f"/opt/{target_dir}"
            programs.append(
                RuntimeProgram(
                    name=name,
                    command=command,
                    directory=directory,
                    autostart=bool(item.get("autostart", True)),
                    autorestart=bool(item.get("autorestart", True)),
                    startsecs=int(item.get("startsecs", 3)),
                    priority=int(item.get("priority", 200)),
                )
            )

    if programs:
        return programs

    raw_commands = runtime.get("commands", [])
    if isinstance(raw_commands, list):
        for idx, item in enumerate(raw_commands, start=1):
            command = str(item).strip()
            if not command:
                continue
            programs.append(
                RuntimeProgram(
                    name=sanitize_program_name(f"{module_name}_{idx}"),
                    command=command,
                    directory=f"/opt/{target_dir}",
                    autostart=True,
                    autorestart=True,
                    startsecs=2,
                    priority=200 + idx,
                )
            )

    return programs


def parse_persistent_paths(module_file: Path, runtime_file: Path) -> list[str]:
    paths: list[str] = []

    module_data = tomllib.loads(module_file.read_text())
    for item in module_data.get("persistence", []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        if path.startswith("/") and path not in paths:
            paths.append(path)

    if runtime_file.exists():
        runtime_data = tomllib.loads(runtime_file.read_text())
        runtime = runtime_data.get("runtime", runtime_data) if isinstance(runtime_data, dict) else {}
        if isinstance(runtime, dict):
            raw = runtime.get("persistent_paths", [])
            if isinstance(raw, str):
                raw = [raw]
            if isinstance(raw, list):
                for item in raw:
                    path = str(item).strip()
                    if path.startswith("/") and path not in paths:
                        paths.append(path)

    return paths


def ensure_citadel_dir(citadel_dir: Path, *, repo_url: str, depth: int, update: bool, dry_run: bool) -> None:
    if citadel_dir.exists():
        if not (citadel_dir / ".git").exists():
            raise RuntimeError(f"CITADEL dir exists but is not a git repo: {citadel_dir}")
        if update:
            run(["git", "-C", str(citadel_dir), "pull", "--ff-only"], dry_run=dry_run)
        else:
            print(f"[skip] CITADEL exists: {citadel_dir}")
        return

    run(["git", "clone", "--depth", str(depth), repo_url, str(citadel_dir)], dry_run=dry_run)


def parse_3rdparty_catalog(citadel_dir: Path) -> dict[str, tuple[str, bool]]:
    out: dict[str, tuple[str, bool]] = {}
    catalog = citadel_dir / "CONTAINER" / "REPOS" / "3rdparty.list"
    if not catalog.exists():
        return out

    for raw in catalog.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        name = parts[0]
        description = parts[5]
        default_selected = parts[6].lower() in {"y", "yes", "1", "true"}
        out[name] = (description, default_selected)

    return out


def find_3rdparty_dir(name: str, workspace: Path, citadel_dir: Path) -> Path | None:
    candidates = [
        workspace / "3RDPARTY" / name,
        citadel_dir / "3RDPARTY" / name,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


def select_3rdparty_directives(mode: str, workspace: Path, citadel_dir: Path) -> list[ThirdPartyDirective]:
    catalog = parse_3rdparty_catalog(citadel_dir)
    selected: list[ThirdPartyDirective] = []

    available: list[ThirdPartyDirective] = []
    for name in THIRDPARTY_NAMES:
        description, default_selected = catalog.get(name, (f"{name} directive", True))
        directory = find_3rdparty_dir(name, workspace, citadel_dir)
        if directory is None:
            print(f"[warn] third-party '{name}' not found in workspace/CITADEL; skipping")
            continue
        available.append(
            ThirdPartyDirective(
                name=name,
                description=description,
                default_selected=default_selected,
                directory=directory,
            )
        )

    if not available:
        return selected

    if mode == "none":
        print("3rd-party integration: disabled  [auto]")
        return selected

    if mode == "all":
        print("3rd-party integration: enabled for all  [auto]")
        return available

    wants_3rdparty = ask_yes_no("3rd-party integrieren?", default=True)
    if not wants_3rdparty:
        return selected

    for item in available:
        include = ask_yes_no(f"{item.name} (3rdparty) -> {item.description}", default=item.default_selected)
        if include:
            selected.append(item)

    return selected


def write_supervisord_conf(path: Path, programs: list[RuntimeProgram]) -> None:
    lines: list[str] = []

    for prog in sorted(programs, key=lambda p: (p.priority, p.name)):
        lines.extend(
            [
                f"[program:{prog.name}]",
                f"directory={prog.directory}",
                f"command=/bin/bash -lc {shlex.quote(prog.command)}",
                f"autostart={'true' if prog.autostart else 'false'}",
                f"autorestart={'true' if prog.autorestart else 'false'}",
                f"startsecs={prog.startsecs}",
                f"priority={prog.priority}",
                "stdout_logfile=/dev/stdout",
                "stdout_logfile_maxbytes=0",
                "stderr_logfile=/dev/stderr",
                "stderr_logfile_maxbytes=0",
                "",
            ]
        )

    if not programs:
        lines.append("# no runtime programs found in runtime.toml")
        lines.append("")

    path.write_text("\n".join(lines) + "\n")


def write_overlay_dockerfile(
    dockerfile_path: Path,
    *,
    base_tag: str,
    repo_rel: str,
    target_dir: str,
    module_rel: str,
    runtime_rel: str,
    module_slug: str,
    supervisor_rel: str,
    thirdparty_copy_lines: list[str],
) -> None:
    copy_3rdparty_block = "\n".join(thirdparty_copy_lines)
    if copy_3rdparty_block:
        copy_3rdparty_block = "\n# Optional 3rd-party payload\n" + copy_3rdparty_block + "\n"

    dockerfile = f"""FROM {base_tag}

# Repo payload
COPY {repo_rel} /opt/{target_dir}

# Python deps (optional)
RUN if [ -f /opt/{target_dir}/requirements.txt ]; then \\
      python3 -m pip install --no-cache-dir -r /opt/{target_dir}/requirements.txt; \\
    fi

# Keep module+runtime metadata inside CITADEL extensions
RUN mkdir -p /opt/citadel/extensions/modules/{module_slug}
COPY {module_rel} /opt/citadel/extensions/modules/{module_slug}/module.toml
COPY {runtime_rel} /opt/citadel/extensions/modules/{module_slug}/runtime.toml
{copy_3rdparty_block}
# Module-level runtime append via supervisord conf.d
COPY {supervisor_rel} /etc/supervisor/conf.d/zz-module-{module_slug}.conf
"""
    dockerfile_path.write_text(dockerfile)


def volume_key_from_path(path: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", path.strip("/"))
    cleaned = re.sub(r"_+", "_", cleaned).strip("_").lower()
    return cleaned or "root"


def write_run_script(
    path: Path,
    *,
    engine_default: str,
    image_tag: str,
    module_slug: str,
    default_tailscale_enabled: bool,
    persistent_paths: list[str],
) -> None:
    tailscale_default = "1" if default_tailscale_enabled else "0"
    mount_lines: list[str] = []

    if persistent_paths:
        mount_lines.append("# Repo/module persistence mounts")
        for p in persistent_paths:
            key = volume_key_from_path(p)
            mount_lines.append(f'MOUNTS+=(--mount "type=volume,source=${{CONTAINER_NAME}}_{key},target={p}")')

    mount_block = "\n".join(mount_lines)
    if mount_block:
        mount_block = "\n" + mount_block + "\n"

    content = f"""#!/usr/bin/env bash
set -euo pipefail

ENGINE="${{ENGINE:-{engine_default}}}"
IMAGE="${{IMAGE:-{image_tag}}}"
CONTAINER_NAME="${{CONTAINER_NAME:-citadel-{module_slug}}}"
HOST_NAME="${{HOST_NAME:-$CONTAINER_NAME}}"
NETWORK="${{NETWORK:-host}}"
CITADEL_ENABLE_TAILSCALE="${{CITADEL_ENABLE_TAILSCALE:-{tailscale_default}}}"

MOUNTS=()
ENV_ARGS=(--env "CITADEL_ENABLE_TAILSCALE=${{CITADEL_ENABLE_TAILSCALE}}")

if [[ -n "${{TS_AUTHKEY:-}}" ]]; then
  ENV_ARGS+=(--env "TS_AUTHKEY=${{TS_AUTHKEY}}")
fi
if [[ -n "${{TS_HOSTNAME:-}}" ]]; then
  ENV_ARGS+=(--env "TS_HOSTNAME=${{TS_HOSTNAME}}")
fi

if [[ "${{CITADEL_ENABLE_TAILSCALE}}" == "1" ]]; then
  MOUNTS+=(--mount "type=volume,source=${{CONTAINER_NAME}}_tailscale_state,target=/var/lib/tailscale")
fi
{mount_block}
if "$ENGINE" ps -a --format '{{{{.Names}}}}' | grep -Fxq "$CONTAINER_NAME"; then
  "$ENGINE" rm -f "$CONTAINER_NAME" >/dev/null
fi

exec "$ENGINE" run \
  --name "$CONTAINER_NAME" \
  --hostname "$HOST_NAME" \
  --network "$NETWORK" \
  "${{MOUNTS[@]}}" \
  "${{ENV_ARGS[@]}}" \
  "$IMAGE"
"""
    path.write_text(content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build from sibling CITADEL Dockerfile + current repo module/runtime; "
            "append runtime as supervisor conf.d and optionally include 3rd-party payload."
        )
    )
    parser.add_argument("--engine", choices=("auto", "podman", "docker"), default="auto")
    parser.add_argument("--workspace", default="", help="Workspace root (default: parent of current repo)")
    parser.add_argument("--citadel-dir", default="", help="Explicit CITADEL directory")
    parser.add_argument("--citadel-repo", default=DEFAULT_CITADEL_REPO)
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--update-citadel", action="store_true")
    parser.add_argument("--base-tag", default="localhost/citadelbasic:base")
    parser.add_argument("--tag", default="", help="Final tag (default: localhost/citadel-<module>:latest)")
    parser.add_argument("--thirdparty", choices=("ask", "all", "none"), default="ask")
    parser.add_argument("--tailscale", choices=("ask", "on", "off"), default="ask")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    script_path = Path(__file__).resolve()
    container_dir = script_path.parent
    repo_root = container_dir.parent

    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else repo_root.parent
    citadel_dir = Path(args.citadel_dir).expanduser().resolve() if args.citadel_dir else (workspace / "CITADEL")

    module_file = container_dir / "module.toml"
    runtime_file = container_dir / "runtime.toml"

    if not module_file.exists():
        raise RuntimeError(f"Missing module file: {module_file}")

    module_name, target_dir = parse_module(module_file, fallback_repo_name=repo_root.name)
    module_slug = sanitize_tag_fragment(module_name)

    base_tag = args.base_tag.strip().lower()
    final_tag = args.tag.strip().lower() if args.tag.strip() else f"localhost/citadel-{module_slug}:latest"

    engine = choose_engine(args.engine)

    print(f"[info] repo: {repo_root}")
    print(f"[info] workspace: {workspace}")
    print(f"[info] citadel_dir: {citadel_dir}")
    print(f"[info] module_name: {module_name}")
    print(f"[info] target_dir: {target_dir}")
    print(f"[info] engine: {engine}")
    print(f"[info] base_tag: {base_tag}")
    print(f"[info] final_tag: {final_tag}")

    if args.tailscale == "on":
        tailscale_enabled = True
        print("tailscale integrieren? [Y/n]: yes  [auto]")
    elif args.tailscale == "off":
        tailscale_enabled = False
        print("tailscale integrieren? [Y/n]: no  [auto]")
    else:
        tailscale_enabled = ask_yes_no("tailscale integrieren?", default=True)

    ensure_citadel_dir(
        citadel_dir,
        repo_url=args.citadel_repo,
        depth=args.depth,
        update=args.update_citadel,
        dry_run=args.dry_run,
    )

    citadel_dockerfile = citadel_dir / "Dockerfile"
    if not citadel_dockerfile.exists():
        raise RuntimeError(f"Missing sibling CITADEL Dockerfile: {citadel_dockerfile}")

    base_build_cmd = [engine, "build", "-f", str(citadel_dockerfile), "-t", base_tag]
    if args.no_cache:
        base_build_cmd.append("--no-cache")
    base_build_cmd.append(str(citadel_dir))
    run(base_build_cmd, dry_run=args.dry_run)

    programs = parse_runtime_programs(runtime_file, module_name=module_name, target_dir=target_dir)
    persistent_paths = parse_persistent_paths(module_file, runtime_file)
    print(f"[info] runtime programs: {len(programs)}")
    print(f"[info] persistent paths: {persistent_paths if persistent_paths else 'none'}")

    selected_thirdparty = select_3rdparty_directives(args.thirdparty, workspace, citadel_dir)
    print(f"[info] selected 3rd-party directives: {', '.join(x.name for x in selected_thirdparty) if selected_thirdparty else 'none'}")

    overlay_dockerfile = container_dir / ".citadel.overlay.Dockerfile"
    supervisor_conf = container_dir / ".citadel.module.supervisord.conf"
    run_script = container_dir / f"citadel_{module_slug}_run.sh"

    write_supervisord_conf(supervisor_conf, programs)

    repo_rel = str(repo_root.relative_to(workspace))
    module_rel = str(module_file.relative_to(workspace))
    runtime_rel = str(runtime_file.relative_to(workspace)) if runtime_file.exists() else str(module_file.relative_to(workspace))
    supervisor_rel = str(supervisor_conf.relative_to(workspace))

    thirdparty_copy_lines: list[str] = []
    if selected_thirdparty:
        thirdparty_copy_lines.append("RUN mkdir -p /opt/citadel/extensions/3RDPARTY")
    for item in selected_thirdparty:
        rel = str(item.directory.relative_to(workspace))
        thirdparty_copy_lines.append(f"COPY {rel} /opt/citadel/extensions/3RDPARTY/{item.name}")

    write_overlay_dockerfile(
        overlay_dockerfile,
        base_tag=base_tag,
        repo_rel=repo_rel,
        target_dir=target_dir,
        module_rel=module_rel,
        runtime_rel=runtime_rel,
        module_slug=module_slug,
        supervisor_rel=supervisor_rel,
        thirdparty_copy_lines=thirdparty_copy_lines,
    )

    final_build_cmd = [engine, "build", "-f", str(overlay_dockerfile), "-t", final_tag]
    if args.no_cache:
        final_build_cmd.append("--no-cache")
    final_build_cmd.append(str(workspace))
    run(final_build_cmd, dry_run=args.dry_run)

    write_run_script(
        run_script,
        engine_default=engine,
        image_tag=final_tag,
        module_slug=module_slug,
        default_tailscale_enabled=tailscale_enabled,
        persistent_paths=persistent_paths,
    )
    if not args.dry_run:
        run(["chmod", "+x", str(run_script)], dry_run=False)

    print(f"[ok] built image: {final_tag}")
    print(f"[ok] run helper: {run_script}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"[error] command failed with exit code {exc.returncode}")
        raise SystemExit(exc.returncode) from exc
    except KeyboardInterrupt:
        print("\n[abort] interrupted")
        raise SystemExit(130)
    except Exception as exc:  # noqa: BLE001
        print(f"[error] {exc}")
        raise SystemExit(1) from exc
