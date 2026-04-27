"""CODEANALYST — FastAPI WebUI."""

import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "functions"))

from python_header import get, get_port  # noqa: F401 — loads .env

import secrets
import uvicorn
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

import core

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
_jinja = Environment(loader=FileSystemLoader(str(BASE_DIR / "templates")))
_jinja.filters["tojson"] = lambda val: json.dumps(val)

# Static files
_static_dir = BASE_DIR / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Simple cookie-based session ID (replaces Flask session)
_SESSION_COOKIE = "codeanalyst_sid"


def _ensure_session(request: Request) -> tuple[str, bool]:
    """Return (sid, is_new)."""
    sid = request.cookies.get(_SESSION_COOKIE, "")
    if sid:
        return sid, False
    return secrets.token_urlsafe(18), True


def _session_response(content, request: Request, status_code: int = 200):
    """Wrap response, setting session cookie if needed."""
    sid, is_new = _ensure_session(request)
    if isinstance(content, dict):
        response = JSONResponse(content, status_code=status_code)
    else:
        response = content
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


async def _safe_json(request: Request) -> dict:
    """Parse JSON body, returning {} on empty/invalid input."""
    try:
        return await request.json()
    except Exception:
        return {}


# ── Pages ──────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    sid, is_new = _ensure_session(request)
    data, scanning, error = core.get_data(sid)
    setup = core.build_setup_payload(sid)
    tmpl = _jinja.get_template("index.html")
    html = tmpl.render(data=data, scanning=scanning, error=error, setup=setup)
    response = HTMLResponse(html)
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


# ── API ────────────────────────────────────────────────────────────────


@app.get("/api/options")
def api_options(request: Request):
    sid, is_new = _ensure_session(request)
    result = core.build_setup_payload(sid)
    response = JSONResponse(result)
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


@app.get("/api/tree")
def api_tree(path: str = Query("", alias="path")):
    raw_path = path.strip()
    if not raw_path:
        return JSONResponse({"error": "Missing path parameter."}, status_code=400)
    result = core.list_directory_children(raw_path)
    if "error" in result and "not found" in result["error"].lower():
        return JSONResponse(result, status_code=404)
    if "error" in result:
        return JSONResponse(result, status_code=403)
    return result


@app.get("/api/data")
def api_data(request: Request):
    sid, is_new = _ensure_session(request)
    data, scanning, error = core.get_data(sid)
    response = JSONResponse({"scanning": scanning, "data": data, "error": error})
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


@app.post("/api/session/reset")
def api_session_reset(request: Request):
    old_sid = request.cookies.get(_SESSION_COOKIE, "")
    new_sid = secrets.token_urlsafe(18)
    if old_sid:
        core.reset_session(old_sid)
    response = JSONResponse({"status": "reset"})
    response.set_cookie(_SESSION_COOKIE, new_sid, httponly=True, samesite="lax")
    return response


@app.get("/api/file")
def api_file(
    project: str = Query("", alias="project"),
    file: str = Query("", alias="file"),
    mode: str = Query("view", alias="mode"),
):
    raw_project = project.strip()
    raw_file = file.strip()
    mode = mode.strip().lower()

    if not raw_project or not raw_file:
        return JSONResponse({"error": "Missing project or file parameter."}, status_code=400)
    if mode not in {"view", "download"}:
        return JSONResponse({"error": "Invalid mode. Use view or download."}, status_code=400)

    result = core.resolve_file(raw_project, raw_file)
    if isinstance(result, dict):
        status = 404 if "not found" in result.get("error", "").lower() else 400
        return JSONResponse(result, status_code=status)

    if mode == "download":
        return FileResponse(result, filename=result.name)
    return FileResponse(result, media_type="text/plain")


@app.get("/api/command-info")
def api_command_info(cmd: str = Query("", alias="cmd")):
    raw_cmd = cmd.strip()
    if not raw_cmd:
        return JSONResponse({"error": "Missing cmd parameter."}, status_code=400)
    if not core.CMD_NAME_RE.match(raw_cmd):
        return JSONResponse({"error": "Invalid command token."}, status_code=400)
    return core.lookup_command_info(raw_cmd)


@app.post("/api/scan/start")
async def api_scan_start(request: Request):
    payload = await _safe_json(request)
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
        return JSONResponse({
            "error": (
                "selected_paths, extra_paths, excluded_paths "
                "and selected_file_types must be arrays."
            )
        }, status_code=400)

    sid, is_new = _ensure_session(request)
    try:
        core.configure_scan_selection(
            sid=sid,
            selected_paths=selected_paths,
            extra_paths=extra_paths,
            excluded_paths=excluded_paths,
            selected_file_types=selected_file_types,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    started, msg = core.start_scan(sid, force=True)
    if not started and msg != "Scan already running.":
        return JSONResponse({"error": msg}, status_code=400)
    response = JSONResponse({"status": "scanning"})
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


@app.post("/api/refresh")
async def api_refresh(request: Request):
    payload = await _safe_json(request)
    sid, is_new = _ensure_session(request)

    selected_file_types = payload.get("selected_file_types")
    if selected_file_types is not None:
        if not isinstance(selected_file_types, list):
            return JSONResponse({"error": "selected_file_types must be an array."}, status_code=400)
        core.update_file_types(sid, selected_file_types)

    started, msg = core.start_scan(sid, force=True)
    if not started and msg != "Scan already running.":
        return JSONResponse({"error": msg}, status_code=400)
    response = JSONResponse({"status": "scanning"})
    if is_new:
        response.set_cookie(_SESSION_COOKIE, sid, httponly=True, samesite="lax")
    return response


# ── Main ──────────────────────────────────────────────────────────────


if __name__ == "__main__":
    host, port = core.load_server_config()
    uvicorn.run(app, host=host, port=port)
