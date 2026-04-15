"""Layer 1 — Input content scanner.

Runs over tool-result and user-role messages on the INBOUND request path (i.e.
after a tool executed and the agent is about to see its output). Looks for
stored prompt-injection patterns and rewrites the content in place so the model
never sees them.

Returns (cleaned_text, list_of_findings). findings are used for audit + alerts.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any


# Cyrillic letters that look like Latin capitals (homoglyph danger when they
# appear as the first letter of an ASCII-text directive like "Ѕystem:").
CYRILLIC_LATIN_LOOKALIKES = set("АВСЕНКМОРТХаеорсухЅӀ")


def _iter_patterns(text: str, patterns: list[str]) -> list[tuple[int, int, str]]:
    """Case-insensitive literal substring matches. Returns (start, end, pattern)."""
    out = []
    lower = text.lower()
    for p in patterns:
        pl = p.lower()
        start = 0
        while True:
            idx = lower.find(pl, start)
            if idx < 0:
                break
            out.append((idx, idx + len(p), p))
            start = idx + len(p)
    return out


def _homoglyph_hits(text: str) -> list[tuple[int, int, str]]:
    """Spot Cyrillic-homoglyph directive starters: the sequence looks like 'System:'
    or similar where the first char is a Cyrillic lookalike rather than Latin."""
    out = []
    # match: homoglyph-letter followed by 1-10 ASCII letters, then ":" or space+":"
    for m in re.finditer(r"([\u0400-\u04ff])([a-zA-Z]{2,10})\s*:", text):
        first = m.group(1)
        if first in CYRILLIC_LATIN_LOOKALIKES:
            normalized = unicodedata.normalize("NFKD", first)
            # If it visually resembles a Latin letter, flag it
            out.append((m.start(), m.end(), f"cyrillic-homoglyph-directive({first}{m.group(2)})"))
    return out


def scan_and_clean(text: str, patterns: list[str]) -> tuple[str, list[dict]]:
    """Scan text for injection patterns + homoglyph directives.

    Replaces each matched span with a placeholder. Returns (cleaned_text, findings).
    findings: [{"pattern": str, "start": int, "end": int, "span": str}]
    """
    if not text:
        return text, []

    findings: list[dict] = []
    hits = _iter_patterns(text, patterns) + _homoglyph_hits(text)
    if not hits:
        return text, []

    # Merge overlapping hits; process from end → start so offsets stay valid.
    hits.sort(key=lambda x: x[0])
    merged: list[tuple[int, int, list[str]]] = []
    for start, end, pat in hits:
        if merged and start <= merged[-1][1]:
            # overlap — extend
            ms, me, mp = merged[-1]
            merged[-1] = (ms, max(me, end), mp + [pat])
        else:
            merged.append((start, end, [pat]))

    out = text
    for start, end, pats in reversed(merged):
        span = out[start:end]
        short = ",".join(sorted(set(pats)))[:80]
        # Extend redaction through the closing HTML comment if we matched an
        # HTML-comment-shaped injection — so the trailing payload is also gone.
        if any("<!-- " in p for p in pats):
            close = out.find("-->", end)
            if 0 <= close <= end + 2000:
                end = close + 3
        placeholder = "[MCPGUARD-REDACTED]"
        out = out[:start] + placeholder + out[end:]
        findings.append({
            "pattern": short,
            "start": start,
            "end": end,
            "span_preview": span[:120],
        })

    return out, findings


def scan_messages(messages: list[dict], patterns: list[str]) -> tuple[list[dict], list[dict]]:
    """Walk a chat `messages` array and clean every tool-result / user text field.

    Returns (possibly-modified messages, list of findings). Messages are
    deep-modified in place; callers that want the original should copy first.
    """
    all_findings: list[dict] = []
    for i, msg in enumerate(messages):
        role = msg.get("role")
        if role not in ("tool", "user"):
            # Still scan system messages for completeness? No — system is trusted.
            continue
        content = msg.get("content")
        if isinstance(content, str):
            cleaned, findings = scan_and_clean(content, patterns)
            if findings:
                msg["content"] = cleaned
                for f in findings:
                    f["message_index"] = i
                    f["role"] = role
                all_findings.extend(findings)
        elif isinstance(content, list):
            # OpenAI-compat structured content: [{"type":"text","text":"..."}, ...]
            for j, part in enumerate(content):
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    cleaned, findings = scan_and_clean(part["text"], patterns)
                    if findings:
                        part["text"] = cleaned
                        for f in findings:
                            f["message_index"] = i
                            f["content_part_index"] = j
                            f["role"] = role
                        all_findings.extend(findings)
    return messages, all_findings
