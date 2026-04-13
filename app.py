"""CODEANALYST — Flask WebUI."""

from python_header import get, get_port  # noqa: F401 — loads .env

import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file, session
from scanner import (
    run_scan,
    discover_project_options,
    normalize_selected_projects,
    resolve_input_dir,
    SKIP_DIRS,
    get_ui_labels,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CODEANALYST_SECRET_KEY") or secrets.token_hex(
    32
)
app.config["SESSION_PERMANENT"] = False

# Cache
_session_caches: dict[str, dict] = {}
_lock = threading.Lock()

CACHE_TTL = 300  # 5 min
SESSION_IDLE_TTL = 8 * 3600  # 8h idle cleanup in RAM
COMMAND_INFO_TTL = 600  # 10 min
VENV_BIN = Path(__file__).parent / "venv" / "bin"
REPO_CACHE_DIR = Path(__file__).parent / ".cache"
SERVER_CONFIG_FILE = Path(__file__).parent / "codeanalyst.server.conf"
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
CMD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")


_cmd_info_cache = {}
_cmd_lock = threading.Lock()


def _load_server_config() -> tuple[str, int]:
    host = "0.0.0.0"
    port = 820

    if not SERVER_CONFIG_FILE.exists():
        return host, port

    for raw_line in SERVER_CONFIG_FILE.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key.lower() == "host" and value:
            host = value
        elif key.lower() == "port" and value:
            try:
                parsed_port = int(value)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port in {SERVER_CONFIG_FILE.name}: {value}"
                ) from exc
            if not (1 <= parsed_port <= 65535):
                raise ValueError(
                    f"Port in {SERVER_CONFIG_FILE.name} must be between 1 and 65535."
                )
            port = parsed_port

    # Env overrides (canonical keys first, legacy alias second).
    host = get("HOST") or get("CODEANALYST_HOST") or host
    port = get_port("CODEANALYST_PORT", port)

    return host, port


def _new_cache_state() -> dict:
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


def _get_session_id() -> str:
    sid = session.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(18)
        session["sid"] = sid
    return str(sid)


def _prune_session_caches(now: float | None = None) -> None:
    now = now or time.time()
    expired = []
    for sid, cache in _session_caches.items():
        last_seen = float(cache.get("last_seen") or 0)
        running = bool(cache.get("running"))
        if running:
            continue
        if (now - last_seen) > SESSION_IDLE_TTL:
            expired.append(sid)
    for sid in expired:
        _session_caches.pop(sid, None)


def _get_or_create_cache(sid: str) -> dict:
    now = time.time()
    with _lock:
        _prune_session_caches(now)
        cache = _session_caches.get(sid)
        if cache is None:
            cache = _new_cache_state()
            _session_caches[sid] = cache
        cache["last_seen"] = now
        return cache


def _reset_current_session_state() -> None:
    old_sid = _get_session_id()
    new_sid = secrets.token_urlsafe(18)
    with _lock:
        _session_caches.pop(old_sid, None)
    session["sid"] = new_sid


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def _normalize_tool_text(text: str) -> str:
    lines = [_strip_ansi(line).rstrip() for line in (text or "").splitlines()]
    compact = []
    for line in lines:
        if line.strip():
            compact.append(line)
            continue
        if compact and compact[-1] != "":
            compact.append("")
    return "\n".join(compact).strip()


def _extract_tldr_summary(text: str) -> str:
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith(">"):
            continue
        line = line.lstrip(">").strip()
        if not line or "Weitere Informationen" in line or "More information" in line:
            continue
        if len(line) > 180:
            return f"{line[:177]}..."
        return line
    return ""


def _extract_summary(text: str) -> str:
    tldr_summary = _extract_tldr_summary(text)
    if tldr_summary:
        return tldr_summary
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("#>").strip()
        if not line:
            continue
        if line.lower().startswith("usage:"):
            continue
        if len(line) > 180:
            line = f"{line[:177]}..."
        return line
    return ""


def _run_tool(
    args: list[str], timeout_sec: int = 3, env_overrides: dict[str, str] | None = None
) -> tuple[bool, str]:
    env = {
        **dict(os.environ),
        "TERM": "dumb",
        "NO_COLOR": "1",
    }
    if env_overrides:
        env.update(env_overrides)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
            check=False,
        )
    except Exception as exc:
        return False, f"{exc}"

    merged = "\n".join(
        part.strip() for part in [proc.stdout or "", proc.stderr or ""] if part.strip()
    )
    return proc.returncode == 0, _normalize_tool_text(merged)


def _is_empty_tool_result(text: str, command: str) -> bool:
    lowered = (text or "").lower()
    if not lowered.strip():
        return True
    if "error fetching from tldr" in lowered:
        return True
    if f"no tldr entry for {command.lower()}" in lowered:
        return True
    return False


def _lookup_command_info(command: str) -> dict:
    key = command.lower()
    now = time.time()
    with _cmd_lock:
        cached = _cmd_info_cache.get(key)
        if cached and (now - cached["ts"]) <= COMMAND_INFO_TTL:
            return cached["payload"]

    ok, text = _run_tool(
        [str(VENV_BIN / "tldr"), "--markdown", command],
        env_overrides={"XDG_CACHE_HOME": str(REPO_CACHE_DIR)},
    )
    found = ok and not _is_empty_tool_result(text, command)
    entry = {
        "source": "tldr",
        "found": bool(found),
        "summary": _extract_summary(text) if found else "",
        "text": text if found else "",
    }
    if not found and text:
        entry["error"] = text.splitlines()[0][:220]

    payload = {"command": command, "sources": [entry]}
    with _cmd_lock:
        _cmd_info_cache[key] = {"payload": payload, "ts": now}
    return payload


def _do_scan(
    sid: str,
    selected_paths_snapshot: list[str],
    excluded_paths_snapshot: list[str],
    selected_file_types_snapshot: list[str],
):
    try:
        data = run_scan(
            selected_projects=selected_paths_snapshot,
            excluded_projects=excluded_paths_snapshot,
            selected_file_types=selected_file_types_snapshot,
        )
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = _new_cache_state()
                _session_caches[sid] = cache
            cache["data"] = data
            cache["ts"] = time.time()
            cache["last_error"] = None
            cache["last_seen"] = time.time()
    except Exception as exc:
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = _new_cache_state()
                _session_caches[sid] = cache
            cache["last_error"] = str(exc)
            cache["last_seen"] = time.time()
    finally:
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = _new_cache_state()
                _session_caches[sid] = cache
            cache["running"] = False
            cache["last_seen"] = time.time()


def get_data():
    sid = _get_session_id()
    cache = _get_or_create_cache(sid)
    return cache["data"], cache["running"], cache["last_error"]


def _configure_scan_selection(
    selected_paths: list[str],
    extra_paths: list[str],
    excluded_paths: list[str],
    selected_file_types: list[str],
):
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

    sid = _get_session_id()
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = _new_cache_state()
            _session_caches[sid] = cache
        cache["selected_paths"] = normalized_selected
        cache["excluded_paths"] = normalized_excluded
        cache["selected_file_types"] = normalized_file_types
        cache["extra_paths"] = sorted(normalized_extra)
        cache["last_seen"] = time.time()


def _build_setup_payload():
    sid = _get_session_id()
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = _new_cache_state()
            _session_caches[sid] = cache
        cache["last_seen"] = time.time()
        extra_paths = list(cache["extra_paths"])
        selected_paths = list(cache["selected_paths"])
        excluded_paths = list(cache["excluded_paths"])
        selected_file_types = list(cache["selected_file_types"])

    options = discover_project_options(extra_paths=extra_paths)
    option_paths = [item["path"] for item in options]

    if selected_paths:
        normalized_selected = [str(p) for p in normalize_selected_projects(selected_paths)]
        selected = normalized_selected
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


def start_scan(force=False):
    sid = _get_session_id()
    with _lock:
        cache = _session_caches.get(sid)
        if cache is None:
            cache = _new_cache_state()
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


@app.route("/")
def index():
    data, scanning, error = get_data()
    setup = _build_setup_payload()
    return render_template(
        "index.html", data=data, scanning=scanning, error=error, setup=setup
    )


@app.route("/api/options")
def api_options():
    return jsonify(_build_setup_payload())


@app.route("/api/tree")
def api_tree():
    raw_path = (request.args.get("path") or "").strip()
    if not raw_path:
        return jsonify({"error": "Missing path parameter."}), 400

    root = resolve_input_dir(raw_path)
    if not root.exists() or not root.is_dir():
        return jsonify({"error": "Directory not found."}), 404

    children = []
    try:
        direct_dirs = sorted(
            [d for d in root.iterdir() if d.is_dir() and d.name not in SKIP_DIRS],
            key=lambda p: p.name.lower(),
        )
    except Exception:
        return jsonify({"error": "Cannot list this directory."}), 403

    for child in direct_dirs:
        has_children = False
        try:
            has_children = any(
                g.is_dir() and g.name not in SKIP_DIRS for g in child.iterdir()
            )
        except Exception:
            has_children = False
        children.append(
            {
                "name": child.name,
                "path": str(child),
                "source": "child",
                "has_children": has_children,
            }
        )

    return jsonify({"path": str(root), "children": children})


@app.route("/api/data")
def api_data():
    data, scanning, error = get_data()
    return jsonify({"scanning": scanning, "data": data, "error": error})


@app.route("/api/session/reset", methods=["POST"])
def api_session_reset():
    _reset_current_session_state()
    return jsonify({"status": "reset"})


@app.route("/api/file")
def api_file():
    raw_project = (request.args.get("project") or "").strip()
    raw_file = (request.args.get("file") or "").strip()
    mode = (request.args.get("mode") or "view").strip().lower()

    if not raw_project or not raw_file:
        return jsonify({"error": "Missing project or file parameter."}), 400
    if mode not in {"view", "download"}:
        return jsonify({"error": "Invalid mode. Use view or download."}), 400

    root = resolve_input_dir(raw_project)
    if not root.exists() or not root.is_dir():
        return jsonify({"error": "Project path not found."}), 404

    rel = Path(raw_file)
    if rel.is_absolute():
        return jsonify({"error": "file must be a relative path."}), 400

    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return jsonify({"error": "File path escapes project root."}), 400

    if not target.exists() or not target.is_file():
        return jsonify({"error": "File not found."}), 404

    as_attachment = mode == "download"
    mimetype = "text/plain" if not as_attachment else None
    return send_file(
        target,
        as_attachment=as_attachment,
        download_name=target.name,
        mimetype=mimetype,
    )


@app.route("/api/command-info")
def api_command_info():
    raw_cmd = (request.args.get("cmd") or "").strip()
    if not raw_cmd:
        return jsonify({"error": "Missing cmd parameter."}), 400
    if not CMD_NAME_RE.match(raw_cmd):
        return jsonify({"error": "Invalid command token."}), 400
    return jsonify(_lookup_command_info(raw_cmd))


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    payload = request.get_json(silent=True) or {}
    selected_paths = payload.get("selected_paths") or []
    extra_paths = payload.get("extra_paths") or []
    excluded_paths = payload.get("excluded_paths") or []
    selected_file_types = payload.get("selected_file_types") or []

    if (
        not isinstance(selected_paths, list)
        or not isinstance(extra_paths, list)
        or not isinstance(excluded_paths, list)
        or not isinstance(selected_file_types, list)
    ):
        return (
            jsonify(
                {
                    "error": (
                        "selected_paths, extra_paths, excluded_paths "
                        "and selected_file_types must be arrays."
                    )
                }
            ),
            400,
        )

    try:
        _configure_scan_selection(
            selected_paths=selected_paths,
            extra_paths=extra_paths,
            excluded_paths=excluded_paths,
            selected_file_types=selected_file_types,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    started, msg = start_scan(force=True)
    if not started and msg != "Scan already running.":
        return jsonify({"error": msg}), 400
    return jsonify({"status": "scanning"})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    payload = request.get_json(silent=True) or {}
    selected_file_types = payload.get("selected_file_types")
    if selected_file_types is not None:
        if not isinstance(selected_file_types, list):
            return jsonify({"error": "selected_file_types must be an array."}), 400
        sid = _get_session_id()
        with _lock:
            cache = _session_caches.get(sid)
            if cache is None:
                cache = _new_cache_state()
                _session_caches[sid] = cache
            cache["selected_file_types"] = [
                str(item).strip()
                for item in selected_file_types
                if str(item).strip()
            ]
            cache["last_seen"] = time.time()

    started, msg = start_scan(force=True)
    if not started and msg != "Scan already running.":
        return jsonify({"error": msg}), 400
    return jsonify({"status": "scanning"})


if __name__ == "__main__":
    host, port = _load_server_config()
    app.run(host=host, port=port, debug=False)
