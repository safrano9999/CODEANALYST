"""
Shared environment bootstrap for all REPOS programs.

Usage — add this as first import in every entrypoint:

    from python_header import env, get, get_int, get_port

How it works:
  1. Loads .env from the calling script's directory (if present)
  2. Loads provider.env (LiteLLM sdk provider keys) if present
  3. Container-injected env vars (--env-file) take precedence
  4. All values are accessible via env dict, get(), or os.environ

Requires: pip install python-dotenv
"""

import os
from pathlib import Path

from dotenv import load_dotenv


def _find_env_file() -> Path:
    """Walk the call stack to find .env next to the calling script."""
    import inspect
    for frame_info in inspect.stack():
        caller_file = frame_info.filename
        if caller_file and not caller_file.startswith("<"):
            candidate = Path(caller_file).resolve().parent / ".env"
            if candidate.exists():
                return candidate
    return Path.cwd() / ".env"


# Load all env files from the script's directory
# .env first, then *.env — override=False means os.environ (container injection) wins
_env_dir = _find_env_file().parent
_dot_env = _env_dir / ".env"
if _dot_env.exists():
    load_dotenv(_dot_env, override=False)
for _ef in sorted(_env_dir.glob("*.env")):
    load_dotenv(_ef, override=False)


def get(key: str, default: str = "") -> str:
    """Get env var as string."""
    return os.environ.get(key, default).strip()


def get_int(key: str, default: int = 0) -> int:
    """Get env var as int, fallback to default on bad input."""
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    """Get env var as bool (1/true/yes/on → True)."""
    raw = os.environ.get(key, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def get_port(key: str, default: int = 8080) -> int:
    """Get env var as validated port number (1-65535)."""
    port = get_int(key, default)
    if not (1 <= port <= 65535):
        raise ValueError(f"{key}={port} is not a valid port (1-65535)")
    return port


# Snapshot for dict-style access: env["KEY"] or env.get("KEY", "default")
env = dict(os.environ)
