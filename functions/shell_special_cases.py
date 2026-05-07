"""Special-case helpers for shell parsing."""

from dataclasses import dataclass
import re

HEREDOC_START_RE = re.compile(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELL_FUNC_DEF_INLINE_RE = re.compile(
    r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?\s*\{"
)
SHELL_FUNC_DEF_HEAD_RE = re.compile(
    r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?\s*$"
)
CASE_START_RE = re.compile(r"^\s*case\b.*\bin\s*$")
CASE_LABEL_RE = re.compile(r"^\s*[^#].*\)\s*(?:;;)?\s*$")
FOR_IN_START_RE = re.compile(r"^\s*for\s+[A-Za-z_][A-Za-z0-9_]*\s+in\b")
DO_TOKEN_RE = re.compile(r"(^|[;\s])do($|[;\s])")
PKG_INSTALL_START_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:"
    r"(?:apt-get|apt)\s+[^#\n]*\binstall\b|"
    r"(?:apk)\s+[^#\n]*\badd\b|"
    r"(?:pacman)\s+[^#\n]*(?:--sync|-S[^\s]*)|"
    r"(?:dnf|yum|microdnf)\s+[^#\n]*\binstall\b|"
    r"(?:zypper)\s+[^#\n]*\b(?:install|in)\b"
    r")",
    re.IGNORECASE,
)
ASSIGNMENT_START_QUOTE_RE = re.compile(
    r"^\s*(?:(?:local|declare|typeset|export|readonly)\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*([\"'])"
)
ASSIGNMENT_ONLY_SUBSHELL_RE = re.compile(
    r"^\s*(?:(?:local|declare|typeset|export|readonly)\s+)?"
    r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:\$\(.+\)|`.+`)\s*(?:#.*)?$"
)


@dataclass
class ShellSpecialState:
    in_case_block: bool = False
    in_for_in_list: bool = False
    in_pkg_install_cont: bool = False


def _has_unescaped_quote(text: str, quote: str) -> bool:
    escaped = False
    for ch in text:
        if quote == '"' and ch == "\\" and not escaped:
            escaped = True
            continue
        if ch == quote and not escaped:
            return True
        escaped = False
    return False


def strip_multiline_assignment_string_bodies(text: str) -> str:
    """Remove multiline assignment string bodies (e.g. QUERY=\"...\" SQL blocks)."""
    lines = text.splitlines()
    out = []
    in_multiline_assign = False
    quote_char = ""
    for line in lines:
        if not in_multiline_assign:
            m = ASSIGNMENT_START_QUOTE_RE.match(line)
            if m:
                q = m.group(1)
                tail = line[m.end() :]
                if not _has_unescaped_quote(tail, q):
                    # Keep assignment start line only; skip body until closing quote.
                    out.append(line[: m.end()])
                    in_multiline_assign = True
                    quote_char = q
                    continue
            out.append(line)
            continue

        if _has_unescaped_quote(line, quote_char):
            in_multiline_assign = False
            quote_char = ""
        # Skip body lines regardless.

    return "\n".join(out)


def strip_shell_heredoc_bodies(text: str) -> str:
    """Remove heredoc bodies so embedded script languages are not parsed as shell."""
    lines = text.splitlines()
    out = []
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        starts = list(HEREDOC_START_RE.finditer(line))
        out.append(line)
        if not starts:
            idx += 1
            continue

        idx += 1
        for match in starts:
            delim = match.group(2)
            allow_tabs = "<<" in match.group(0) and "<<-" in match.group(0)
            while idx < len(lines):
                current = lines[idx]
                candidate = current.lstrip("\t") if allow_tabs else current
                if candidate == delim:
                    idx += 1
                    break
                idx += 1

    return "\n".join(out)


def extract_shell_function_names(text: str) -> set[str]:
    names: set[str] = set()
    lines = text.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line.strip().startswith("#"):
            idx += 1
            continue

        m_inline = SHELL_FUNC_DEF_INLINE_RE.match(line)
        if m_inline:
            names.add(m_inline.group(1).lower())
            idx += 1
            continue

        m_head = SHELL_FUNC_DEF_HEAD_RE.match(line)
        if m_head:
            name = m_head.group(1).lower()
            probe = idx + 1
            while probe < len(lines) and not lines[probe].strip():
                probe += 1
            if probe < len(lines) and lines[probe].strip().startswith("{"):
                names.add(name)
            idx += 1
            continue

        idx += 1
    return names


def preprocess_shell_text(text: str) -> tuple[str, set[str]]:
    prepared = strip_multiline_assignment_string_bodies(text)
    prepared = strip_shell_heredoc_bodies(prepared)
    return prepared, extract_shell_function_names(prepared)


def should_skip_line_before_parse(stripped: str, state: ShellSpecialState) -> bool:
    if not stripped:
        return True
    if stripped.startswith("#"):
        return True
    if ASSIGNMENT_ONLY_SUBSHELL_RE.match(stripped):
        return True

    if state.in_for_in_list:
        # Skip multiline "for ... in" list items; they are data, not commands.
        if DO_TOKEN_RE.search(stripped):
            state.in_for_in_list = False
        return True

    if CASE_START_RE.match(stripped):
        state.in_case_block = True
        return True
    if state.in_case_block and stripped == "esac":
        state.in_case_block = False
        return True
    if state.in_case_block and CASE_LABEL_RE.match(stripped):
        # case pattern labels like "foo|bar)" are not command invocations
        return True
    return False


def apply_pkg_continuation_state(
    line: str, state: ShellSpecialState
) -> tuple[str, bool]:
    if not state.in_pkg_install_cont:
        return line, False
    # Skip package-list continuation lines after package-manager install/add/sync.
    # If a command chain starts on the same line (&& / || / ;),
    # resume parsing from that operator onward.
    chain_match = re.search(r"(\&\&|\|\||;)", line)
    if chain_match:
        state.in_pkg_install_cont = False
        return line[chain_match.end() :].strip(), False

    if not line.rstrip().endswith("\\"):
        state.in_pkg_install_cont = False
    return "", True


def update_state_after_parse(stripped: str, line: str, state: ShellSpecialState) -> None:
    if FOR_IN_START_RE.match(stripped) and not DO_TOKEN_RE.search(stripped):
        state.in_for_in_list = True
    if PKG_INSTALL_START_RE.search(line) and line.rstrip().endswith("\\"):
        state.in_pkg_install_cont = True
