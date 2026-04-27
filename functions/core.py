"""
core.py — CODEANALYST business logic.
No Flask/HTTP dependencies.
"""

import os
import re
import subprocess
import threading
import time
from pathlib import Path

from scanner import (
    run_scan,
    discover_project_options,
    normalize_selected_projects,
    resolve_input_dir,
    SKIP_DIRS,
    get_ui_labels,
)

# ── Constants ──────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent

CACHE_TTL = 300  # 5 min
SESSION_IDLE_TTL = 8 * 3600  # 8h
COMMAND_INFO_TTL = 600  # 10 min
VENV_BIN = BASE_DIR / "venv" / "bin"
REPO_CACHE_DIR = BASE_DIR / ".cache"
SERVER_CONFIG_FILE = BASE_DIR / "codeanalyst.server.conf"

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
CMD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")

# Session caches (keyed by session ID)
_session_caches: dict[str, dict] = {}
_lock = threading.Lock()

# Command info cache
_cmd_info_cache: dict = {}
_cmd_lock = threading.Lock()


# ── Server Config ──────────────────────────────────────────────────────


def load_server_config() -> tuple[str, int]:
    """Read host/port from .conf file, with env overrides."""
    host = "0.0.0.0"
    port = 820

    if SERVER_CONFIG_FILE.exists():
        for raw_line in SERVER_CONFIG_FILE.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key.lower() == "host" and value:
                host = value
            elif key.lower() == "port" and value:
                parsed_port = int(value)
                if not (1 <= parsed_port <= 65535):
                    raise ValueError(
                        f"Port in {SERVER_CONFIG_FILE.name} must be 1-65535."
                    )
                port = parsed_port

    host = os.environ.get("HOST") or os.environ.get("CODEANALYST_HOST") or host
    env_port = os.environ.get("CODEANALYST_PORT")
    if env_port:
        port = int(env_port)

    return host, port


# ── Session Cache ──────────────────────────────────────────────────────


def new_cache_state() -> dict:
    return {
        "data": None,
        "ts": 0,
        "running": False,
        "selected_paths": [],
        "excluded_paths": [],
        "selected_file_types": [],
        "extra_paths": [],
        "last_error": None,
        "last_seen": time.time(),
    }


def _prune_session_caches(now: float | None = None) -> None:
    now = now or time.time()
    expired = [
        sid
        for sid, cache in _session_caches.items()
        if not cache.get("running")
        and (now - float(cache.get("last_seen") or 0)) > SESSION_IDLE_TTL
    ]
    for sid in expired:
        _session_caches.pop(sid, None)


def get_or_create_cache(sid: str) -> dict:
    now = time.time()
    with _lock:
        _prune_session_caches(now)
        cache = _session_caches.get(sid)
        if cache is None:
            cache = new_cache_state()
            _session_caches[sid] = cache
        cache["last_seen"] = now
        return cache


def reset_session(old_sid: str) -> None:
    """Remove all cache state for a session."""
    with _lock:
        _session_caches.pop(old_sid, None)


def get_data(sid: str) -> tuple:
    """Return (data, running, last_error) for a session."""
    cache = get_or_create_cache(sid)
    return cache["data"], cache["running"], cache["last_error"]


# ── Text Processing ──────────────────────────────────────────────────


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def normalize_tool_text(text: str) -> str:
    lines = [strip_ansi(line).rstrip() for line in (text or "").splitlines()]
    compact = []
    for line in lines:
        if line.strip():
            compact.append(line)
        elif compact and compact[-1] != "":
            compact.append("")
    return "\n".join(compact).strip()


def extract_summary(text: str) -> str:
    """Extract a one-line summary from tldr or help text."""
    # Try tldr format first
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith(">"):
            continue
        line = line.lstrip(">").strip()
        if not line or "Weitere Informationen" in line or "More information" in line:
            continue
        return line[:177] + "..." if len(line) > 180 else line

    # Fallback: first meaningful line
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("#>").strip()
        if not line or line.lower().startswith("usage:"):
            continue
        return line[:177] + "..." if len(line) > 180 else line
    return ""


# ── Tool Execution ──────────────────────────────────────────────────


def run_tool(
    args: list[str], timeout_sec: int = 3, env_overrides: dict[str, str] | None = None
) -> tuple[bool, str]:
    env = {**dict(os.environ), "TERM": "dumb", "NO_COLOR": "1"}
    if env_overrides:
        env.update(env_overrides)
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_sec, env=env, check=False
        )
    except Exception as exc:
        return False, f"{exc}"
    merged = "\n".join(
        part.strip() for part in [proc.stdout or "", proc.stderr or ""] if part.strip()
    )
    return proc.returncode == 0, normalize_tool_text(merged)


def is_empty_tool_result(text: str, command: str) -> bool:
    lowered = (text or "").lower()
    if not lowered.strip():
        return True
    if "error fetching from tldr" in lowered:
        return True
    if f"no tldr entry for {command.lower()}" in lowered:
        return True
    return False


# ── Command Info Lookup ──────────────────────────────────────────────


def lookup_command_info(command: str) -> dict:
    """Look up command docs via tldr, with caching."""
    key = command.lower()
    now = time.time()
    with _cmd_lock:
        cached = _cmd_info_cache.get(key)
        if cached and (now - cached["ts"]) <= COMMAND_INFO_TTL:
            return cached["payload"]

    ok, text = run_tool(
        [str(VENV_BIN / "tldr"), "--markdown", command],
        env_overrides={"XDG_CACHE_HOME": str(REPO_CACHE_DIR)},
    )
    found = ok and not is_empty_tool_result(text, command)
    entry = {
        "source": "tldr",
        "found": bool(found),
        "summary": extract_summary(text) if found else "",
        "text": text if found else "",
    }
    if not found and text:
        entry["error"] = text.splitlines()[0][:220]

    payload = {"command": command, "sources": [entry]}
    with _cmd_lock:
        _cmd_info_cache[key] = {"payload": payload, "ts": now}
    return payload


# ── Directory Browsing ───────────────────────────────────────────────


def list_directory_children(raw_path: str) -> dict:
    """List subdirectories for the tree browser."""
    root = resolve_input_dir(raw_path)
    if not root.exists() or not root.is_dir():
        return {"error": "Directory not found."}

    children = []
    try:
        direct_dirs = sorted(
            [d for d in root.iterdir() if d.is_dir() and d.name not in SKIP_DIRS],
            key=lambda p: p.name.lower(),
        )
    except Exception:
        return {"error": "Cannot list this directory."}

    for child in direct_dirs:
        has_children = False
        try:
            has_children = any(
                g.is_dir() and g.name not in SKIP_DIRS for g in child.iterdir()
            )
        except Exception:
            pass
        children.append({
            "name": child.name,
            "path": str(child),
            "source": "child",
            "has_children": has_children,
        })

    return {"path": str(root), "children": children}


def resolve_file(project: str, file: str) -> dict | Path:
    """Resolve and validate a file path within a project. Returns Path or error dict."""
    root = resolve_input_dir(project)
    if not root.exists() or not root.is_dir():
        return {"error": "Project path not found."}

    rel = Path(file)
    if rel.is_absolute():
        return {"error": "file must be a relative path."}

    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {"error": "File path escapes project root."}

    if not target.exists() or not target.is_file():
        return {"error": "File not found."}

    return target


# ── Scan ──────────────────────────────────────────────────────────────


def configure_scan_selection(
    sid: str,
    selected_paths: list[str],
    extra_paths: list[str],
    excluded_paths: list[str],
    selected_file_types: list[str],
):
    """Normalize and store scan selection for a session."""
    normalized_selected = [str(p) for p in normalize_selected_projects(selected_paths)]
    normalized_extra = {str(p) for p in normalize_selected_projects(extra_paths)}
    normalized_excluded = [str(p) for p in normalize_selected_projects(excluded_paths)]
    normalized_file_types = []
    seen_types = set()
    for raw in selected_file_types or []:
        item = str(raw).strip()
        if not item or item in seen_types:
            continue
        seen_types.add(item)
        normalized_file_types.append(item)

    if not normalized_selected:
        raise ValueError("No valid directories selected.")

    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = new_cache_state()
            _session_caches[sid] = cache
        cache["selected_paths"] = normalized_selected
        cache["excluded_paths"] = normalized_excluded
        cache["selected_file_types"] = normalized_file_types
        cache["extra_paths"] = sorted(normalized_extra)
        cache["last_seen"] = time.time()


def update_file_types(sid: str, file_types: list[str]):
    """Update selected file types for a session."""
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = new_cache_state()
            _session_caches[sid] = cache
        cache["selected_file_types"] = [
            str(item).strip() for item in file_types if str(item).strip()
        ]
        cache["last_seen"] = time.time()


def build_setup_payload(sid: str) -> dict:
    """Build the project selection / setup payload for the UI."""
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = new_cache_state()
            _session_caches[sid] = cache
        cache["last_seen"] = time.time()
        extra_paths = list(cache["extra_paths"])
        selected_paths = list(cache["selected_paths"])
        excluded_paths = list(cache["excluded_paths"])
        selected_file_types = list(cache["selected_file_types"])

    options = discover_project_options(extra_paths=extra_paths)
    option_paths = [item["path"] for item in options]

    if selected_paths:
        selected = [str(p) for p in normalize_selected_projects(selected_paths)]
    else:
        selected = option_paths.copy()

    return {
        "projects": options,
        "selected_paths": selected,
        "excluded_paths": excluded_paths,
        "selected_file_types": selected_file_types,
        "extra_paths": extra_paths,
        "ui": get_ui_labels(),
    }


def _do_scan(
    sid: str,
    selected_paths: list[str],
    excluded_paths: list[str],
    selected_file_types: list[str],
):
    try:
        data = run_scan(
            selected_projects=selected_paths,
            excluded_projects=excluded_paths,
            selected_file_types=selected_file_types,
        )
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = new_cache_state()
                _session_caches[sid] = cache
            cache["data"] = data
            cache["ts"] = time.time()
            cache["last_error"] = None
            cache["last_seen"] = time.time()
    except Exception as exc:
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = new_cache_state()
                _session_caches[sid] = cache
            cache["last_error"] = str(exc)
            cache["last_seen"] = time.time()
    finally:
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = new_cache_state()
                _session_caches[sid] = cache
            cache["running"] = False
            cache["last_seen"] = time.time()


def start_scan(sid: str, force: bool = False) -> tuple[bool, str]:
    """Start a background scan for a session. Returns (started, message)."""
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = new_cache_state()
            _session_caches[sid] = cache
        if cache["running"]:
            return False, "Scan already running."

        selected = list(cache["selected_paths"])
        excluded = list(cache["excluded_paths"])
        selected_file_types = list(cache["selected_file_types"])
        has_fresh_data = (
            cache["data"] is not None and (time.time() - cache["ts"]) <= CACHE_TTL
        )
        if not selected:
            return False, "No directories selected."
        if has_fresh_data and not force:
            return False, "Scan results are still fresh."

        cache["running"] = True
        cache["last_error"] = None
        cache["last_seen"] = time.time()

    t = threading.Thread(
        target=_do_scan,
        args=(sid, selected, excluded, selected_file_types),
        daemon=True,
    )
    t.start()
    return True, "scanning"
