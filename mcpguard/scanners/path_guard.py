"""Layer 3 — Sensitive path guard.

Checks tool_call arguments for dangerous filesystem targets. Matches the path
against fnmatch-style globs from config, with normalization (backslash →
forward slash, lowercase). Returns verdict + reason.
"""

from __future__ import annotations

import fnmatch
from typing import Any


FILE_WRITE_TOOLS = frozenset({
    "write", "edit", "apply_patch", "create", "create_file",
    "fs.write", "fs.edit", "replace_in_file",
})
FILE_READ_TOOLS = frozenset({"read", "fs.read", "read_file", "cat"})
PATH_ARG_CANDIDATES = ("path", "file_path", "filepath", "target", "dest", "destination")


def _normalize(p: str) -> str:
    return p.replace("\\", "/").lower()


def _extract_path(args: dict[str, Any]) -> str | None:
    if not isinstance(args, dict):
        return None
    for k in PATH_ARG_CANDIDATES:
        if isinstance(args.get(k), str):
            return args[k]
    # edit/apply_patch sometimes nest path inside edits list
    edits = args.get("edits")
    if isinstance(edits, list) and edits:
        first = edits[0]
        if isinstance(first, dict):
            for k in PATH_ARG_CANDIDATES:
                if isinstance(first.get(k), str):
                    return first[k]
    return None


def check_write(tool_name: str, arguments: dict, deny_write_globs: list[str]) -> tuple[str, str | None]:
    """Return ('allow'|'block', reason-or-None) for a potential write-type tool call."""
    if tool_name not in FILE_WRITE_TOOLS:
        return "allow", None
    path = _extract_path(arguments)
    if not path:
        return "allow", None
    norm = _normalize(path)
    for glob in deny_write_globs:
        g = glob.lower()
        if fnmatch.fnmatch(norm, g):
            return "block", f"write to protected path {path!r} matches deny-glob {glob!r}"
        # Also match against a basename-anchored version so "**/.env" catches "foo/.env"
        # fnmatch treats "**" as a sequence of any chars — should already work, but
        # be defensive for patterns that don't have a prefix wildcard
        if fnmatch.fnmatch(norm, "*/" + g.lstrip("*/")) or norm.endswith("/" + g.lstrip("*/")):
            return "block", f"write to protected path {path!r} matches deny-glob {glob!r}"
    return "allow", None


def path_matches_read_then_send(path: str, deny_globs: list[str]) -> bool:
    """Used by chain_detector: is this path in the 'read then don't let it
    leave the machine' protected set?"""
    if not path:
        return False
    norm = _normalize(path)
    for glob in deny_globs:
        g = glob.lower()
        if fnmatch.fnmatch(norm, g):
            return True
    return False


def is_read_tool(tool_name: str) -> bool:
    return tool_name in FILE_READ_TOOLS


def is_write_tool(tool_name: str) -> bool:
    return tool_name in FILE_WRITE_TOOLS


def extract_path(args: dict) -> str | None:
    return _extract_path(args)
