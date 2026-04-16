"""CODEANALYST — source code scanner for external Linux program usage."""

import os
import re
import ast
import shlex
from pathlib import Path
from collections import defaultdict
from fnmatch import fnmatch
from shell_special_cases import (
    ShellSpecialState,
    preprocess_shell_text,
    should_skip_line_before_parse,
    apply_pkg_continuation_state,
    update_state_after_parse,
)

# ── Config ────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).parent / "codeanalyst.conf"
LISTINGS_DIR = Path(__file__).parent / "Listings"

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh",
    ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts",
    ".php", ".rb", ".pl",
    ".toml", ".yaml", ".yml",
    ".json",  # package.json scripts etc.
    ".md",    # README shell blocks
    "Dockerfile", ".dockerfile",
}

# Directories to always skip
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv",
    "vendor", "dist", "build", ".hermes", ".cache",
    "site-packages", "lib", ".npm", ".local",
}

DEFAULT_NON_PROGRAM_TOKENS = {
    "break",
    "case",
    "continue",
    "declare",
    "def",
    "do",
    "done",
    "echo",
    "elif",
    "else",
    "esac",
    "except",
    "exit",
    "fi",
    "for",
    "from",
    "function",
    "if",
    "import",
    "local",
    "new",
    "return",
    "select",
    "set",
    "shift",
    "then",
    "trap",
    "true",
    "wait",
    "while",
    "with",
}
DEFAULT_BASH_SHELL_TOKENS = {
    "if",
    "then",
    "fi",
    "for",
    "do",
    "done",
    "while",
    "case",
    "esac",
    "elif",
    "else",
    "local",
    "return",
    "exit",
    "set",
    "shift",
    "break",
    "continue",
    "declare",
    "function",
    "select",
    "wait",
    "trap",
    "echo",
    "read",
    "source",
    "true",
}
DEFAULT_BASH_SHELL_PATTERNS = {"*.sh", "*.bash", "*.zsh", "Dockerfile", "Makefile", "Procfile"}

DEFAULT_PYTHON_TOKENS = {
    "if",
    "elif",
    "else",
    "for",
    "while",
    "break",
    "continue",
    "def",
    "return",
    "import",
    "from",
    "with",
    "except",
    "try",
    "finally",
    "class",
    "pass",
    "raise",
    "yield",
    "lambda",
    "await",
    "async",
}
DEFAULT_PYTHON_PATTERNS = {"*.py"}

DEFAULT_JS_TS_NPM_TOKENS = {
    "if",
    "else",
    "for",
    "while",
    "break",
    "continue",
    "function",
    "return",
    "import",
    "export",
    "const",
    "let",
    "var",
    "class",
    "new",
    "try",
    "catch",
    "finally",
    "await",
    "async",
}
DEFAULT_JS_TS_NPM_PATTERNS = {
    "*.js",
    "*.ts",
    "*.mjs",
    "*.cjs",
    "*.jsx",
    "*.tsx",
    "*.mts",
    "*.cts",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
}

SHELL_FILE_SUFFIXES = {".sh", ".bash", ".zsh"}
JS_FILE_SUFFIXES = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts"}
CONFIG_FILE_SUFFIXES = {".json", ".yaml", ".yml", ".toml"}
SHELL_FENCE_LANGS = {"bash", "sh", "shell", "zsh", "console"}

SHELL_SPLIT_RE = re.compile(r"\|\||&&|[|;]")
MARKDOWN_FENCE_RE = re.compile(r"```([^\n`]*)\n(.*?)```", re.DOTALL)
PY_SUBPROCESS_RE = re.compile(
    r"subprocess\.\w+\s*\(\s*(?:\[\s*)?[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
PY_OS_RE = re.compile(
    r"os\.(?:system|popen|execv?[pe]?)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
JS_EXEC_RE = re.compile(
    r"(?:child_process\.)?(?:execFileSync|execFile|execSync|exec|spawnSync|spawn)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
GENERIC_EXEC_RE = re.compile(
    r"(?:system|popen|exec)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
CONFIG_CMD_RE = re.compile(
    r"(?im)^\s*(?:command|cmd|script|entrypoint)\s*[:=]\s*[\"']?([^\"'\n#]+)"
)
CMD_TOKEN_RE = re.compile(r"^[a-z0-9_][a-z0-9+_.-]*$")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
URL_PREFIX_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
DOMAIN_LIKE_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)
WORD_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PY_SUBPROCESS_FUNCS = {
    "run",
    "popen",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
}
PY_OS_FUNCS = {
    "system",
    "popen",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "execl",
    "execlp",
    "execlpe",
    "spawnl",
    "spawnlp",
    "spawnv",
    "spawnvp",
    "spawnve",
    "spawnvpe",
}
PKG_OPTS_WITH_VALUE_COMMON = {
    "-C",
    "-D",
    "-R",
    "-b",
    "-c",
    "-o",
    "-r",
    "-t",
    "-X",
    "--arch",
    "--cachedir",
    "--cache-dir",
    "--config",
    "--config-file",
    "--keys-dir",
    "--option",
    "--releasever",
    "--repo",
    "--repoid",
    "--repofrompath",
    "--repositories-file",
    "--root",
    "--setopt",
    "--target-release",
    "--virtual",
}
PKG_MANAGERS = {"apt", "apt-get", "apk", "pacman", "dnf", "yum", "microdnf", "zypper"}


def _read_listing_lines(name: str, defaults: set[str]) -> list[str]:
    path = LISTINGS_DIR / name
    if path.exists() and path.is_file():
        try:
            lines = [
                line.strip()
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if lines:
                return lines
        except Exception:
            pass
    return sorted(defaults)


def _listing_patterns_to_type_keys(patterns: list[str]) -> list[str]:
    """Convert listing patterns into file-type keys used by the UI filter."""
    keys = set()
    for raw in patterns:
        p = str(raw).strip()
        if not p:
            continue
        p = p.replace("\\", "/")
        p_base = p.rsplit("/", 1)[-1]
        p_low = p_base.lower()
        if p_low.startswith("*."):
            keys.add(p_low)
            continue
        if p_base in {"Dockerfile", "Makefile", "Procfile"}:
            keys.add(p_base)
            continue
        dot = p_low.rfind(".")
        if dot > 0:
            keys.add(f"*{p_low[dot:]}")
    return sorted(keys)


def _read_listing_lines_alias(names: tuple[str, ...], defaults: set[str]) -> list[str]:
    for name in names:
        lines = _read_listing_lines(name, set())
        if lines:
            return lines
    return sorted(defaults)


def _looks_like_file_pattern(line: str) -> bool:
    if any(ch in line for ch in "*?[]/\\"):
        return True
    if line in {"Dockerfile", "Makefile", "Procfile"}:
        return True
    if "." in line and not line.startswith("$"):
        return True
    return False


def _split_mode_listing(
    lines: list[str], default_tokens: set[str], default_patterns: set[str]
) -> tuple[list[str], list[str]]:
    tokens = set()
    patterns = set()
    for raw in lines:
        item = raw.strip()
        if not item:
            continue
        if _looks_like_file_pattern(item):
            patterns.add(item)
        else:
            tokens.add(item.lower())
    if not tokens:
        tokens = {t.lower() for t in default_tokens}
    if not patterns:
        patterns = set(default_patterns)
    return sorted(tokens), sorted(patterns)


def _load_mode_listing(
    primary_name: str,
    aliases: tuple[str, ...],
    default_tokens: set[str],
    default_patterns: set[str],
) -> tuple[list[str], list[str]]:
    lines = _read_listing_lines_alias((primary_name, *aliases), set())
    return _split_mode_listing(lines, default_tokens, default_patterns)


def _mode_id_from_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")


def _discover_ui_modes() -> list[dict[str, object]]:
    modes: list[dict[str, object]] = []
    if LISTINGS_DIR.exists() and LISTINGS_DIR.is_dir():
        for entry in sorted(LISTINGS_DIR.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_file():
                continue
            if entry.name in {"Syntax", "Shell", "Python"}:
                continue
            lines = _read_listing_lines_alias((entry.name,), set())
            tokens, patterns = _split_mode_listing(lines, set(), set())
            if not tokens:
                if entry.name == "BASH_SHELL":
                    tokens = sorted(DEFAULT_BASH_SHELL_TOKENS)
                elif entry.name == "PYTHON":
                    tokens = sorted(DEFAULT_PYTHON_TOKENS)
                elif entry.name == "JS_TS_NPM":
                    tokens = sorted(DEFAULT_JS_TS_NPM_TOKENS)
            if not patterns:
                if entry.name == "BASH_SHELL":
                    patterns = sorted(DEFAULT_BASH_SHELL_PATTERNS)
                elif entry.name == "PYTHON":
                    patterns = sorted(DEFAULT_PYTHON_PATTERNS)
                elif entry.name == "JS_TS_NPM":
                    patterns = sorted(DEFAULT_JS_TS_NPM_PATTERNS)
            file_types = _listing_patterns_to_type_keys(patterns)
            if not file_types:
                continue
            modes.append(
                {
                    "id": _mode_id_from_name(entry.name),
                    "label": entry.name,
                    "file_types": file_types,
                    "tokens": [str(t).strip().lower() for t in tokens if str(t).strip()],
                    "patterns": [str(p).strip() for p in patterns if str(p).strip()],
                }
            )

    if not modes:
        modes = [
            {
                "id": "bash_shell",
                "label": "BASH_SHELL",
                "file_types": _listing_patterns_to_type_keys(
                    sorted(DEFAULT_BASH_SHELL_PATTERNS)
                ),
                "tokens": sorted(DEFAULT_BASH_SHELL_TOKENS),
                "patterns": sorted(DEFAULT_BASH_SHELL_PATTERNS),
            },
            {
                "id": "python",
                "label": "PYTHON",
                "file_types": _listing_patterns_to_type_keys(
                    sorted(DEFAULT_PYTHON_PATTERNS)
                ),
                "tokens": sorted(DEFAULT_PYTHON_TOKENS),
                "patterns": sorted(DEFAULT_PYTHON_PATTERNS),
            },
            {
                "id": "js_ts_npm",
                "label": "JS_TS_NPM",
                "file_types": _listing_patterns_to_type_keys(
                    sorted(DEFAULT_JS_TS_NPM_PATTERNS)
                ),
                "tokens": sorted(DEFAULT_JS_TS_NPM_TOKENS),
                "patterns": sorted(DEFAULT_JS_TS_NPM_PATTERNS),
            },
        ]
    return modes


BASH_SHELL_TOKENS, BASH_SHELL_LISTING_PATTERNS = _load_mode_listing(
    "BASH_SHELL",
    ("Shell",),
    DEFAULT_BASH_SHELL_TOKENS,
    DEFAULT_BASH_SHELL_PATTERNS,
)
PYTHON_TOKENS, PYTHON_LISTING_PATTERNS = _load_mode_listing(
    "PYTHON",
    ("Python",),
    DEFAULT_PYTHON_TOKENS,
    DEFAULT_PYTHON_PATTERNS,
)
JS_TS_NPM_TOKENS, JS_TS_NPM_LISTING_PATTERNS = _load_mode_listing(
    "JS_TS_NPM",
    tuple(),
    DEFAULT_JS_TS_NPM_TOKENS,
    DEFAULT_JS_TS_NPM_PATTERNS,
)
LEGACY_SYNTAX_TOKENS = {
    t.lower() for t in _read_listing_lines_alias(("Syntax",), set())
}
NON_PROGRAM_TOKENS = set(DEFAULT_NON_PROGRAM_TOKENS)
NON_PROGRAM_TOKENS.update(BASH_SHELL_TOKENS)
NON_PROGRAM_TOKENS.update(PYTHON_TOKENS)
NON_PROGRAM_TOKENS.update(JS_TS_NPM_TOKENS)
NON_PROGRAM_TOKENS.update(LEGACY_SYNTAX_TOKENS)
MODE_DEFINITIONS = _discover_ui_modes()
MODE_TOKEN_SETS = {
    str(mode.get("id")): {str(t).lower() for t in (mode.get("tokens") or [])}
    for mode in MODE_DEFINITIONS
}
MODE_PATTERNS = {
    str(mode.get("id")): [str(p) for p in (mode.get("patterns") or [])]
    for mode in MODE_DEFINITIONS
}
NON_PROGRAM_FILE_PATTERNS = sorted(
    {
        str(pattern).strip().lower()
        for patterns in MODE_PATTERNS.values()
        for pattern in patterns
        if str(pattern).strip()
    }
)


def get_ui_labels() -> dict[str, dict]:
    modes = MODE_DEFINITIONS
    return {
        "modes": modes,
        "mode_file_types": {
            mode["id"]: mode["file_types"] for mode in modes
        },
    }


def path_matches_patterns(path: Path, patterns: list[str]) -> bool:
    name = path.name
    rel = str(path).replace("\\", "/")
    name_l = name.lower()
    rel_l = rel.lower()
    for pattern in patterns:
        p = pattern.strip()
        if not p:
            continue
        if fnmatch(name, p) or fnmatch(rel, p):
            return True
        p_l = p.lower()
        if fnmatch(name_l, p_l) or fnmatch(rel_l, p_l):
            return True
    return False


def is_shell_script_file(path: Path) -> bool:
    return path_matches_patterns(path, BASH_SHELL_LISTING_PATTERNS)


def is_python_script_file(path: Path) -> bool:
    return path_matches_patterns(path, PYTHON_LISTING_PATTERNS)


def is_js_ts_npm_file(path: Path) -> bool:
    return path_matches_patterns(path, JS_TS_NPM_LISTING_PATTERNS)


def merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for key, value in source.items():
        target[key] += value


def normalize_command(raw: str | None) -> str | None:
    if not raw:
        return None
    token = raw.strip().strip('\'"`').rstrip(")]},")
    if URL_PREFIX_RE.match(token):
        return None
    if token.startswith("./"):
        token = token[2:]
    if "/" in token:
        token = token.rsplit("/", 1)[-1]
    token = token.lower()
    return token or None


def is_program_token(token: str | None) -> bool:
    if not token:
        return False
    token_l = token.lower()
    # Script-like tokens that match Listing file wildcards (e.g. *.sh, *.py)
    # are file names, not external programs.
    for pattern in NON_PROGRAM_FILE_PATTERNS:
        if fnmatch(token_l, pattern):
            return False
    if token in NON_PROGRAM_TOKENS:
        return False
    if token_l.startswith("www."):
        return False
    if DOMAIN_LIKE_RE.match(token_l):
        return False
    if token_l.startswith("$"):
        return False
    if token_l.isdigit():
        return False
    return bool(CMD_TOKEN_RE.match(token_l))


def add_detected_token(
    token: str | None,
    program_counts: dict[str, int],
    blacklist_counts: dict[str, int],
) -> None:
    if not token:
        return
    if token in NON_PROGRAM_TOKENS:
        blacklist_counts[token] += 1
        return
    if is_program_token(token):
        program_counts[token] += 1


def first_command_token(segment: str) -> str | None:
    tokens = split_shell_words(segment)
    if not tokens:
        return None

    idx = 0
    while idx < len(tokens):
        raw_tok = tokens[idx]
        tok = raw_tok
        if tok in {"sudo", "command"}:
            idx += 1
            continue
        # Shell assignment with whitespace: "name = value" is not a command.
        if (
            VAR_NAME_RE.match(tok)
            and idx + 1 < len(tokens)
            and tokens[idx + 1] == "="
        ):
            return None
        if ENV_ASSIGN_RE.match(raw_tok) or ENV_ASSIGN_RE.match(tok):
            rhs = raw_tok.split("=", 1)[1] if "=" in raw_tok else tok.split("=", 1)[1]
            # Assignment statements with command/arithmetic substitution
            # are not environment prefixes for an external command.
            if "$(" in rhs or "`" in rhs:
                return None
            # Bash array assignments like AGENTS=(a b c) are declarations,
            # not command prefixes.
            if rhs.lstrip().startswith("("):
                return None
            idx += 1
            continue
        return tok
    return None


def count_shell_lines(
    text: str, *, require_prompt: bool = False
) -> tuple[dict[str, int], dict[str, int]]:
    program_counts = defaultdict(int)
    blacklist_counts = defaultdict(int)
    text, local_functions = preprocess_shell_text(text)
    state = ShellSpecialState()
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if should_skip_line_before_parse(stripped, state):
            continue

        line = stripped
        if require_prompt:
            if not line.startswith("$"):
                continue
            line = line[1:].lstrip()

        line, skip_line = apply_pkg_continuation_state(line, state)
        if skip_line:
            continue
        if not line:
            continue

        for segment in SHELL_SPLIT_RE.split(line):
            cmd = normalize_command(first_command_token(segment))
            if cmd and cmd in local_functions:
                continue
            add_detected_token(cmd, program_counts, blacklist_counts)

        update_state_after_parse(stripped, line, state)

    return program_counts, blacklist_counts


def extract_docker_shell_parts(text: str) -> list[str]:
    """Return logical RUN/CMD/ENTRYPOINT shell parts from a Dockerfile."""
    logical_lines: list[str] = []
    continued = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        if not continued and (not stripped or stripped.startswith("#")):
            continue

        if stripped.endswith("\\"):
            chunk = stripped[:-1].strip()
            if continued:
                continued = f"{continued} {chunk}".strip()
            else:
                continued = chunk
            continue

        if continued:
            stripped = f"{continued} {stripped}".strip()
            continued = ""

        if stripped:
            logical_lines.append(stripped)

    if continued:
        logical_lines.append(continued)

    shell_parts: list[str] = []
    for line in logical_lines:
        parts = line.split(None, 1)
        if not parts:
            continue
        directive = parts[0].lower()
        if directive not in {"run", "cmd", "entrypoint"}:
            continue
        shell_part = parts[1] if len(parts) > 1 else ""
        if shell_part:
            shell_parts.append(shell_part)
    return shell_parts


def split_shell_words(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except Exception:
        return segment.strip().split()


def normalize_package_token(raw: str) -> str | None:
    token = str(raw or "").strip().strip("'\"`").strip(",")
    if not token:
        return None
    if token in {"--", "\\"}:
        return None
    if token.startswith("$") or token.startswith("${"):
        return None
    if token.startswith(("./", "../", "~/")):
        return None
    if "/" in token:
        return None
    if token.startswith("-"):
        return None

    # Strip version pinning / arch suffix where present.
    if "=" in token and not token.startswith("="):
        token = token.split("=", 1)[0].strip()
    if ":" in token and not token.startswith(":"):
        token = token.split(":", 1)[0].strip()
    token = token.lower()
    if not token:
        return None
    if not CMD_TOKEN_RE.match(token):
        return None
    if token in PKG_MANAGERS:
        return None
    return token


def collect_package_names(
    args: list[str], options_with_value: set[str] | None = None
) -> dict[str, int]:
    counts = defaultdict(int)
    opts = options_with_value or set()
    skip_next = False
    for raw in args:
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token in {"&&", "||", ";", "|"}:
            continue
        if token.startswith("-"):
            if token in opts:
                skip_next = True
            continue
        name = normalize_package_token(token)
        if name:
            counts[name] += 1
    return counts


def extract_packages_from_words(words: list[str]) -> dict[str, int]:
    counts = defaultdict(int)
    if not words:
        return counts

    idx = 0
    while idx < len(words):
        tok = str(words[idx]).strip()
        tok_l = tok.lower()
        if not tok:
            idx += 1
            continue
        if tok_l in {"sudo", "doas", "command"}:
            idx += 1
            continue
        if ENV_ASSIGN_RE.match(tok):
            idx += 1
            continue
        break

    if idx >= len(words):
        return counts

    cmd = normalize_command(words[idx])
    if not cmd:
        return counts
    args = [str(v) for v in words[idx + 1 :]]

    def merge(src: dict[str, int]) -> None:
        for k, v in src.items():
            counts[k] += v

    if cmd in {"apt", "apt-get"}:
        install_at = next((i for i, t in enumerate(args) if t == "install"), -1)
        if install_at >= 0:
            merge(collect_package_names(args[install_at + 1 :], PKG_OPTS_WITH_VALUE_COMMON))
        return counts

    if cmd == "apk":
        add_at = next((i for i, t in enumerate(args) if t == "add"), -1)
        if add_at >= 0:
            merge(collect_package_names(args[add_at + 1 :], PKG_OPTS_WITH_VALUE_COMMON))
        return counts

    if cmd == "pacman":
        sync_at = -1
        for i, t in enumerate(args):
            if t == "--sync" or (t.startswith("-S") and len(t) >= 2):
                sync_at = i
                break
        if sync_at >= 0:
            merge(collect_package_names(args[sync_at + 1 :], PKG_OPTS_WITH_VALUE_COMMON))
        return counts

    if cmd in {"dnf", "yum", "microdnf"}:
        install_at = next((i for i, t in enumerate(args) if t == "install"), -1)
        if install_at >= 0:
            merge(collect_package_names(args[install_at + 1 :], PKG_OPTS_WITH_VALUE_COMMON))
        return counts

    if cmd == "zypper":
        install_at = next((i for i, t in enumerate(args) if t in {"install", "in"}), -1)
        if install_at >= 0:
            merge(collect_package_names(args[install_at + 1 :], PKG_OPTS_WITH_VALUE_COMMON))
        return counts

    return counts


def extract_package_counts_from_shell(text: str) -> dict[str, int]:
    counts = defaultdict(int)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for segment in SHELL_SPLIT_RE.split(line):
            words = split_shell_words(segment)
            seg_counts = extract_packages_from_words(words)
            merge_counts(counts, seg_counts)
    return dict(counts)


def extract_package_counts_for_file(path: Path, text: str) -> dict[str, int]:
    suffix = path.suffix.lower()
    name = path.name
    counts = defaultdict(int)
    if name == "Dockerfile" or suffix == ".dockerfile":
        for shell_part in extract_docker_shell_parts(text):
            merge_counts(counts, extract_package_counts_from_shell(shell_part))
        return dict(counts)
    if (
        is_shell_script_file(path)
        or suffix in SHELL_FILE_SUFFIXES
        or name in {"Makefile", "Procfile"}
    ):
        merge_counts(counts, extract_package_counts_from_shell(text))
    return dict(counts)


def extract_markdown_commands(text: str) -> tuple[dict[str, int], dict[str, int]]:
    program_counts = defaultdict(int)
    blacklist_counts = defaultdict(int)
    for match in MARKDOWN_FENCE_RE.finditer(text):
        lang = match.group(1).strip().lower()
        block = match.group(2)
        if lang in SHELL_FENCE_LANGS:
            block_programs, block_blacklist = count_shell_lines(block)
            merge_counts(program_counts, block_programs)
            merge_counts(blacklist_counts, block_blacklist)
        elif not lang:
            # For unlabeled blocks, only count prompt-like lines to avoid prose noise.
            block_programs, block_blacklist = count_shell_lines(
                block, require_prompt=True
            )
            merge_counts(program_counts, block_programs)
            merge_counts(blacklist_counts, block_blacklist)
    return program_counts, blacklist_counts


def extract_quoted_commands(
    text: str, pattern: re.Pattern
) -> tuple[dict[str, int], dict[str, int]]:
    program_counts = defaultdict(int)
    blacklist_counts = defaultdict(int)
    for raw in pattern.findall(text):
        for segment in SHELL_SPLIT_RE.split(raw):
            cmd = normalize_command(first_command_token(segment))
            add_detected_token(cmd, program_counts, blacklist_counts)
    return program_counts, blacklist_counts


def count_mode_tokens(text: str, token_set: set[str]) -> dict[str, int]:
    if not token_set:
        return {}
    counts = defaultdict(int)
    for token in WORD_TOKEN_RE.findall(text.lower()):
        if token in token_set:
            counts[token] += 1
    return dict(counts)


def mode_script_marker(path: Path, patterns: list[str]) -> str | None:
    """Return file-name marker for wildcard script patterns like *.sh / *.py."""
    name_l = path.name.lower()
    for raw in patterns or []:
        p = str(raw).strip().lower()
        if not p.startswith("*."):
            continue
        if fnmatch(name_l, p):
            return name_l
    return None


def _collect_py_call_target(func: ast.AST) -> tuple[str | None, str | None]:
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        if (
            isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
        ):
            return f"{func.value.value.id}.{func.value.attr}", func.attr
    return None, None


def _is_interesting_python_exec(owner: str | None, name: str | None) -> bool:
    if not name:
        return False
    owner_l = (owner or "").lower()
    name_l = name.lower()
    if owner_l == "subprocess" and name_l in PY_SUBPROCESS_FUNCS:
        return True
    if owner_l == "os" and name_l in PY_OS_FUNCS:
        return True
    if owner_l == "asyncio" and name_l in {
        "create_subprocess_exec",
        "create_subprocess_shell",
    }:
        return True
    return False


def _discover_python_exec_wrappers(tree: ast.AST) -> dict[str, int]:
    wrappers: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        params = [arg.arg for arg in node.args.args]
        if not params:
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call) or not inner.args:
                continue
            owner, name = _collect_py_call_target(inner.func)
            if not _is_interesting_python_exec(owner, name):
                continue
            first = inner.args[0]
            if isinstance(first, ast.Name) and first.id in params:
                wrappers[node.name] = params.index(first.id)
                break
    return wrappers


def _extract_python_expr_commands(
    expr: ast.AST, assignments: dict[str, list[str]]
) -> list[str]:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value]

    if isinstance(expr, ast.Name):
        return assignments.get(expr.id, [])

    if isinstance(expr, (ast.List, ast.Tuple)):
        if not expr.elts:
            return []
        first = _extract_python_expr_commands(expr.elts[0], assignments)
        if first:
            return first
        # Fallback: sometimes first item is dynamic and second is still a command literal.
        if len(expr.elts) > 1:
            return _extract_python_expr_commands(expr.elts[1], assignments)
        return []

    if isinstance(expr, ast.Call):
        if expr.args:
            return _extract_python_expr_commands(expr.args[0], assignments)
        return []

    if isinstance(expr, ast.BinOp):
        right = _extract_python_expr_commands(expr.right, assignments)
        if right:
            return right
        return _extract_python_expr_commands(expr.left, assignments)

    return []


def extract_python_commands_ast(
    text: str,
) -> tuple[dict[str, int], dict[str, int], bool]:
    program_counts = defaultdict(int)
    blacklist_counts = defaultdict(int)

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return program_counts, blacklist_counts, False

    assignments: dict[str, list[str]] = {}
    wrapper_param_index = _discover_python_exec_wrappers(tree)

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign):  # type: ignore[override]
            commands = _extract_python_expr_commands(node.value, assignments)
            if commands:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = commands
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign):  # type: ignore[override]
            if node.value is not None and isinstance(node.target, ast.Name):
                commands = _extract_python_expr_commands(node.value, assignments)
                if commands:
                    assignments[node.target.id] = commands
            self.generic_visit(node)

        def visit_For(self, node: ast.For):  # type: ignore[override]
            if isinstance(node.target, ast.Name) and isinstance(
                node.iter, (ast.List, ast.Tuple, ast.Set)
            ):
                collected: list[str] = []
                for elt in node.iter.elts:
                    collected.extend(_extract_python_expr_commands(elt, assignments))
                if collected:
                    # Keep unique while preserving order.
                    seen = set()
                    ordered = []
                    for cmd in collected:
                        if cmd in seen:
                            continue
                        seen.add(cmd)
                        ordered.append(cmd)
                    assignments[node.target.id] = ordered
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call):  # type: ignore[override]
            owner, name = _collect_py_call_target(node.func)
            interesting = _is_interesting_python_exec(owner, name)

            if interesting and node.args:
                raw_cmds = _extract_python_expr_commands(node.args[0], assignments)
                for raw in raw_cmds:
                    for segment in SHELL_SPLIT_RE.split(raw):
                        cmd = normalize_command(first_command_token(segment))
                        add_detected_token(cmd, program_counts, blacklist_counts)
            elif isinstance(node.func, ast.Name):
                wrapper_name = node.func.id
                if wrapper_name in wrapper_param_index:
                    arg_idx = wrapper_param_index[wrapper_name]
                    if arg_idx < len(node.args):
                        raw_cmds = _extract_python_expr_commands(
                            node.args[arg_idx], assignments
                        )
                        for raw in raw_cmds:
                            for segment in SHELL_SPLIT_RE.split(raw):
                                cmd = normalize_command(first_command_token(segment))
                                add_detected_token(
                                    cmd, program_counts, blacklist_counts
                                )

            self.generic_visit(node)

    Visitor().visit(tree)
    return program_counts, blacklist_counts, True


# ── Loader ────────────────────────────────────────────────────────────

def load_scan_paths():
    """Load scan paths from config file."""
    paths = []
    config_dir = CONFIG_FILE.parent
    if not CONFIG_FILE.exists():
        return [config_dir.parent]

    for line in CONFIG_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = Path(os.path.expanduser(line))
        if not p.is_absolute():
            p = (config_dir / p).resolve()
        else:
            p = p.resolve()
        if p.exists():
            paths.append(p)
    return paths


def resolve_input_dir(raw_path: str | Path) -> Path:
    """Resolve a user-provided directory path."""
    p = Path(os.path.expanduser(str(raw_path).strip()))
    if not p.is_absolute():
        p = (CONFIG_FILE.parent / p).resolve()
    else:
        p = p.resolve()
    return p


def discover_project_options(extra_paths: list[str] | None = None) -> list[dict]:
    """Discover selectable project directories from config roots + extra paths."""
    options = []
    seen = set()

    for root in load_scan_paths():
        if not root.is_dir():
            continue
        for subdir in sorted(
            [d for d in root.iterdir() if d.is_dir() and d.name not in SKIP_DIRS],
            key=lambda p: p.name.lower(),
        ):
            key = str(subdir)
            if key in seen:
                continue
            seen.add(key)
            options.append({"name": subdir.name, "path": key, "source": "config"})

    for raw in extra_paths or []:
        p = resolve_input_dir(raw)
        if not p.exists() or not p.is_dir() or p.name in SKIP_DIRS:
            continue
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        options.append({"name": p.name, "path": key, "source": "extra"})

    return sorted(options, key=lambda item: (item["name"].lower(), item["path"]))


def normalize_selected_projects(selected_paths: list[str] | None) -> list[Path]:
    """Normalize selected project paths to existing unique directories."""
    normalized = []
    seen = set()
    for raw in selected_paths or []:
        p = resolve_input_dir(raw)
        key = str(p)
        if key in seen:
            continue
        if not p.exists() or not p.is_dir() or p.name in SKIP_DIRS:
            continue
        seen.add(key)
        normalized.append(p)
    return normalized


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def reduce_selected_roots(selected_paths: list[Path]) -> list[Path]:
    """Keep only top-most selected roots to avoid duplicate nested scans."""
    reduced: list[Path] = []
    for p in sorted(selected_paths, key=lambda item: (len(item.parts), str(item))):
        if any(path_is_within(p, root) for root in reduced):
            continue
        reduced.append(p)
    return reduced


def normalize_excluded_projects(
    excluded_paths: list[str] | None, selected_roots: list[Path]
) -> list[Path]:
    """Normalize excludes and keep only paths that are descendants of selected roots."""
    excluded = normalize_selected_projects(excluded_paths)
    selected_set = {str(p) for p in selected_roots}
    filtered = []
    seen = set()
    for ex in sorted(excluded, key=lambda item: (len(item.parts), str(item))):
        if str(ex) in selected_set:
            continue
        if not any(path_is_within(ex, root) and ex != root for root in selected_roots):
            continue
        key = str(ex)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(ex)
    return filtered


# ── Scanner ───────────────────────────────────────────────────────────

def file_type_key(path: Path) -> str:
    """Return a normalized file-type label used for runtime filtering."""
    name = path.name
    if name in {"Dockerfile", "Makefile", "Procfile"}:
        return name
    suffix = path.suffix.lower()
    if suffix:
        return f"*{suffix}"
    return "(no-ext)"


def is_scannable_type(path: Path) -> bool:
    """Check whether this file type is supported by the scanner."""
    if path.name in SKIP_DIRS:
        return False
    if (
        is_shell_script_file(path)
        or is_python_script_file(path)
        or is_js_ts_npm_file(path)
    ):
        return True
    suffix = path.suffix.lower()
    name = path.name
    return suffix in SCAN_EXTENSIONS or name in {"Dockerfile", "Makefile", "Procfile"}


def should_scan_file(path: Path, selected_file_types: set[str] | None = None) -> bool:
    """Check if file should be scanned for this run."""
    if not is_scannable_type(path):
        return False
    if not selected_file_types:
        return True
    return file_type_key(path) in selected_file_types


def scan_file(path: Path) -> dict:
    """Scan a single file."""
    program_counts = defaultdict(int)
    blacklist_counts = defaultdict(int)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {"programs": {}, "blacklist": {}}

    suffix = path.suffix.lower()
    name = path.name
    is_dockerfile = name == "Dockerfile" or suffix == ".dockerfile"
    is_makefile = name == "Makefile"
    mode_syntax_counts: dict[str, dict[str, int]] = {}
    package_counts_cache: dict[str, int] | None = None

    if (
        is_shell_script_file(path)
        or suffix in SHELL_FILE_SUFFIXES
        or name == "Procfile"
    ) and not is_dockerfile and not is_makefile:
        block_programs, block_blacklist = count_shell_lines(text)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)

    if is_dockerfile:
        for shell_part in extract_docker_shell_parts(text):
            block_programs, block_blacklist = count_shell_lines(shell_part)
            merge_counts(program_counts, block_programs)
            merge_counts(blacklist_counts, block_blacklist)

    if is_makefile:
        recipe_lines = "\n".join(
            line.lstrip() for line in text.splitlines() if line.startswith("\t")
        )
        block_programs, block_blacklist = count_shell_lines(recipe_lines)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)

    if is_python_script_file(path) or suffix == ".py":
        block_programs, block_blacklist, parsed = extract_python_commands_ast(text)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)
        # Fallback for partial/broken Python files where AST parsing fails.
        if not parsed:
            block_programs, block_blacklist = extract_quoted_commands(
                text, PY_SUBPROCESS_RE
            )
            merge_counts(program_counts, block_programs)
            merge_counts(blacklist_counts, block_blacklist)
            block_programs, block_blacklist = extract_quoted_commands(text, PY_OS_RE)
            merge_counts(program_counts, block_programs)
            merge_counts(blacklist_counts, block_blacklist)
    elif is_js_ts_npm_file(path) or suffix in JS_FILE_SUFFIXES:
        block_programs, block_blacklist = extract_quoted_commands(text, JS_EXEC_RE)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)
    elif suffix in {".php", ".rb", ".pl"}:
        block_programs, block_blacklist = extract_quoted_commands(text, GENERIC_EXEC_RE)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)
    elif suffix == ".md":
        block_programs, block_blacklist = extract_markdown_commands(text)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)
    elif suffix in CONFIG_FILE_SUFFIXES:
        block_programs, block_blacklist = extract_quoted_commands(text, CONFIG_CMD_RE)
        merge_counts(program_counts, block_programs)
        merge_counts(blacklist_counts, block_blacklist)

    for mode in MODE_DEFINITIONS:
        mode_id = str(mode.get("id") or "").strip()
        if not mode_id:
            continue
        patterns = MODE_PATTERNS.get(mode_id) or []
        if patterns and not path_matches_patterns(path, patterns):
            continue

        if mode_id == "packages":
            if package_counts_cache is None:
                package_counts_cache = extract_package_counts_for_file(path, text)
            if package_counts_cache:
                mode_syntax_counts[mode_id] = dict(package_counts_cache)
            continue

        token_counts = count_mode_tokens(text, MODE_TOKEN_SETS.get(mode_id, set()))
        marker = mode_script_marker(path, patterns)
        if marker:
            token_counts[marker] = token_counts.get(marker, 0) + 1
        if token_counts:
            mode_syntax_counts[mode_id] = token_counts

    return {
        "programs": dict(program_counts),
        "blacklist": dict(blacklist_counts),
        "mode_syntax": mode_syntax_counts,
    }


def scan_project(
    root: Path,
    excluded_dirs: list[Path] | None = None,
    selected_file_types: set[str] | None = None,
) -> dict:
    """Scan a project directory. Returns structured results."""
    project_name = root.name
    file_results = {}  # file_path -> {program: count}
    blacklist_file_results = {}  # file_path -> {blacklist_token: count}
    mode_file_results = {
        str(mode.get("id")): {} for mode in MODE_DEFINITIONS if mode.get("id")
    }
    program_totals = defaultdict(int)
    blacklist_totals = defaultdict(int)
    mode_totals = {
        str(mode.get("id")): defaultdict(int)
        for mode in MODE_DEFINITIONS
        if mode.get("id")
    }
    available_file_types = defaultdict(int)
    files_scanned = 0
    files_skipped = 0
    excluded_dirs = excluded_dirs or []

    def is_excluded(path: Path) -> bool:
        return any(path_is_within(path, ex) for ex in excluded_dirs)

    if is_excluded(root):
        return {
            "name": project_name,
            "path": str(root),
            "files_scanned": 0,
            "files_skipped": 0,
            "programs": {},
            "files": {},
            "blacklist": {},
            "blacklist_files": {},
            "mode_totals": {},
            "mode_files": {},
            "file_types_available": {},
        }

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        if is_excluded(current):
            dirnames[:] = []
            continue

        # Prune skip dirs in-place
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIRS and not is_excluded(current / d)
        ]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            if is_excluded(fpath):
                continue
            if is_scannable_type(fpath):
                available_file_types[file_type_key(fpath)] += 1
            if not should_scan_file(fpath, selected_file_types=selected_file_types):
                files_skipped += 1
                continue
            result = scan_file(fpath)
            prog_counts = result["programs"]
            blacklist_counts = result["blacklist"]
            mode_counts = result.get("mode_syntax", {})
            if prog_counts or blacklist_counts or any(mode_counts.values()):
                rel = str(fpath.relative_to(root))
                if prog_counts:
                    file_results[rel] = prog_counts
                if blacklist_counts:
                    blacklist_file_results[rel] = blacklist_counts
                for prog, cnt in prog_counts.items():
                    program_totals[prog] += cnt
                for token, cnt in blacklist_counts.items():
                    blacklist_totals[token] += cnt
                for mode_id, token_counts in mode_counts.items():
                    if not token_counts:
                        continue
                    mode_file_results.setdefault(mode_id, {})
                    mode_totals.setdefault(mode_id, defaultdict(int))
                    mode_file_results[mode_id][rel] = token_counts
                    for token, cnt in token_counts.items():
                        mode_totals[mode_id][token] += cnt
            files_scanned += 1

    return {
        "name": project_name,
        "path": str(root),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "programs": dict(sorted(program_totals.items(), key=lambda x: -x[1])),
        "files": file_results,
        "blacklist": dict(sorted(blacklist_totals.items(), key=lambda x: -x[1])),
        "blacklist_files": blacklist_file_results,
        "mode_totals": {
            mode_id: dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
            for mode_id, counts in mode_totals.items()
            if counts
        },
        "mode_files": {
            mode_id: files
            for mode_id, files in mode_file_results.items()
            if files
        },
        "file_types_available": dict(
            sorted(available_file_types.items(), key=lambda x: (-x[1], x[0]))
        ),
    }


def run_scan(
    selected_projects: list[str] | None = None,
    excluded_projects: list[str] | None = None,
    selected_file_types: list[str] | None = None,
) -> dict:
    """Full scan across selected projects, with optional excluded descendants."""
    if selected_projects is None:
        project_dirs = [Path(item["path"]) for item in discover_project_options()]
        excluded_dirs: list[Path] = []
    else:
        normalized_selected = normalize_selected_projects(selected_projects)
        project_dirs = reduce_selected_roots(normalized_selected)
        excluded_dirs = normalize_excluded_projects(excluded_projects, project_dirs)

    scan_paths = sorted({str(p.parent) for p in project_dirs})
    projects = []
    global_totals = defaultdict(int)
    blacklist_global_totals = defaultdict(int)
    mode_global_totals = {
        str(mode.get("id")): defaultdict(int)
        for mode in MODE_DEFINITIONS
        if mode.get("id")
    }
    file_type_global_totals = defaultdict(int)
    selected_file_type_set = {
        str(item).strip() for item in (selected_file_types or []) if str(item).strip()
    }
    if not selected_file_type_set:
        selected_file_type_set = None

    for project_dir in project_dirs:
        project_excludes = [
            ex for ex in excluded_dirs if path_is_within(ex, project_dir) and ex != project_dir
        ]
        result = scan_project(
            project_dir,
            excluded_dirs=project_excludes,
            selected_file_types=selected_file_type_set,
        )
        for ftype, cnt in result.get("file_types_available", {}).items():
            file_type_global_totals[ftype] += cnt
        mode_totals_project = result.get("mode_totals", {})
        has_mode_hits = any(bool(v) for v in mode_totals_project.values())
        if result["programs"] or result["blacklist"] or has_mode_hits:
            projects.append(result)
            for prog, cnt in result["programs"].items():
                global_totals[prog] += cnt
            for token, cnt in result["blacklist"].items():
                blacklist_global_totals[token] += cnt
            for mode_id, counts in mode_totals_project.items():
                mode_global_totals.setdefault(mode_id, defaultdict(int))
                for token, cnt in counts.items():
                    mode_global_totals[mode_id][token] += cnt

    available_sorted = dict(
        sorted(file_type_global_totals.items(), key=lambda x: (-x[1], x[0]))
    )
    if selected_file_type_set is None:
        selected_file_types_final = list(available_sorted.keys())
    else:
        selected_file_types_final = [
            key for key in available_sorted.keys() if key in selected_file_type_set
        ]

    return {
        "projects": projects,
        "global": dict(sorted(global_totals.items(), key=lambda x: -x[1])),
        "blacklist_global": dict(
            sorted(blacklist_global_totals.items(), key=lambda x: -x[1])
        ),
        "mode_global": {
            mode_id: dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
            for mode_id, counts in mode_global_totals.items()
            if counts
        },
        "file_types_global": available_sorted,
        "selected_file_types": selected_file_types_final,
        "total_projects": len(projects),
        "scan_paths": scan_paths,
        "selected_projects": [str(p) for p in project_dirs],
        "excluded_projects": [str(p) for p in excluded_dirs],
    }
