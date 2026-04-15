"""Layer 5 — Rate limiter / anomaly detection.

Counts, derived freshly from the messages array each turn, of:
  - Total tool_calls ever made in this conversation
  - File reads
  - Web-fetch-style calls
  - Same-domain web-fetches
  - Bytes read

If adding the NEW tool_call would push over any configured threshold, BLOCK.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from . import chain_detector, path_guard


WEB_FETCH_TOOLS = frozenset({
    "web_fetch", "fetch", "http_request", "web.get", "web.post",
    "urlFetch", "net.fetch", "net.post",
})
URL_RE = chain_detector.URL_RE


def _domains_in_args(args: dict) -> list[str]:
    blob = chain_detector._args_as_string(args)
    return [m.group(1).lower() for m in URL_RE.finditer(blob)]


def summarize_history(messages: list[dict]) -> dict[str, Any]:
    """Count tool-calls / reads / fetches / bytes-read from the conversation so far."""
    tool_call_count = 0
    read_count = 0
    web_fetch_count = 0
    domain_counts: Counter = Counter()
    bytes_read = 0

    # tool_call_id -> (name, args)
    calls_by_id: dict[str, tuple[str, dict]] = {}
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            tool_call_count += 1
            fn = tc.get("function") or {}
            name = (fn.get("name") or tc.get("name") or "").lower()
            args = fn.get("arguments") or tc.get("arguments") or {}
            if isinstance(args, str):
                import json
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"_raw": args}
            if not isinstance(args, dict):
                args = {}
            tcid = tc.get("id") or tc.get("tool_call_id")
            if tcid:
                calls_by_id[tcid] = (name, args)
            if path_guard.is_read_tool(name):
                read_count += 1
            if name in WEB_FETCH_TOOLS or any(s in name for s in ("fetch", "http", "web", "url", "net")):
                web_fetch_count += 1
                for d in _domains_in_args(args):
                    domain_counts[d] += 1

    # bytes read: sum of tool-result content lengths for read-tools
    for m in messages:
        if m.get("role") != "tool":
            continue
        tcid = m.get("tool_call_id")
        name, _ = calls_by_id.get(tcid, ("", {}))
        if not path_guard.is_read_tool(name):
            continue
        content = m.get("content")
        if isinstance(content, list):
            content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
        if isinstance(content, str):
            bytes_read += len(content.encode("utf-8", errors="replace"))

    return {
        "tool_call_count": tool_call_count,
        "read_count": read_count,
        "web_fetch_count": web_fetch_count,
        "domain_counts": dict(domain_counts),
        "bytes_read": bytes_read,
    }


def check_new_tool_call(
    tool_name: str,
    arguments: dict,
    history_summary: dict,
    limits: dict,
) -> tuple[str, str | None]:
    """Decide if the proposed new tool_call would exceed a limit. ('allow'|'block', reason)."""
    tc = history_summary["tool_call_count"] + 1
    if tc > limits.get("max_tool_calls_per_prompt", 10):
        return "block", (f"rate-limit: tool_call #{tc} exceeds "
                          f"max_tool_calls_per_prompt="
                          f"{limits['max_tool_calls_per_prompt']}")
    name = (tool_name or "").lower()
    if path_guard.is_read_tool(name):
        rc = history_summary["read_count"] + 1
        if rc > limits.get("max_file_reads_per_prompt", 5):
            return "block", (f"rate-limit: file-read #{rc} exceeds "
                              f"max_file_reads_per_prompt="
                              f"{limits['max_file_reads_per_prompt']}")
    web_like = (name in WEB_FETCH_TOOLS or
                any(s in name for s in ("fetch", "http", "web", "url", "net")))
    if web_like:
        wf = history_summary["web_fetch_count"] + 1
        if wf > limits.get("max_web_fetch_per_session", 20):
            return "block", (f"rate-limit: web-fetch #{wf} exceeds "
                              f"max_web_fetch_per_session="
                              f"{limits['max_web_fetch_per_session']}")
        # same-domain limit
        for d in _domains_in_args(arguments):
            cur = history_summary["domain_counts"].get(d, 0) + 1
            lim = limits.get("max_same_domain_web_fetch_per_session", 5)
            if cur > lim:
                return "block", (f"rate-limit: same-domain web-fetch #{cur} to {d!r} "
                                  f"exceeds {lim}")
    return "allow", None


def check_read_result_size(content: str, limits: dict) -> tuple[str, str | None]:
    mx = limits.get("max_read_size_bytes", 2_097_152)
    size = len(content.encode("utf-8", errors="replace"))
    if size > mx:
        return "block", (f"rate-limit: read-result size {size} exceeds "
                         f"max_read_size_bytes={mx}")
    return "allow", None
