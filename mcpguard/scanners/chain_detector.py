"""Layer 4 — Exfiltration chain detector + semantic DLP.

Tracks state across tool calls within a session:

  - Every tool-result message we see (role=tool, from previous reads) is
    hashed and chunked. We extract high-entropy tokens and also build a
    set of substrings of the raw content (8-char sliding-window hashes).
  - On each new outbound tool_call, we check whether its arguments contain:
      * The full sha256 of any previously-read file (or its prefix/suffix)
      * Any high-entropy token previously seen
      * Base64 of any previously-read file (decoded + substring-match)
      * URL-path slices of any previously-read file's sha256
      * Any hex40+ / JWT / SSH-key / AWS-key shaped string (raw DLP)
  - Additionally, we enforce the "read protected file + send externally"
    sequence: if ANY prior read touched a path in deny_read_then_send, a
    subsequent tool_call whose args contain an external URL gets BLOCKED
    regardless of whether we can prove the file content is in the body.

All of this is derived freshly from the `messages` array each turn — no
persistent session state needed outside the audit log.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
from collections import Counter
from typing import Any

from . import path_guard


URL_RE = re.compile(r"https?://([^\s/'\"`<>]+)(/[^\s'\"`<>]*)?", re.IGNORECASE)

# Tools that can EXFILTRATE without being named "fetch"/"web"/"http":
#   - cron:          schedules tasks; delivery mode "webhook" with `to` URL
#   - sessions_spawn:spawns a subagent given a task string
#   - subagents:     similar
#   - webchat/send:  posts to a messaging channel
#   - sessions_send: sends to a session (which may be channel-bound)
HIGH_RISK_TOOL_NAMES = frozenset({
    "cron", "sessions_spawn", "subagents", "webchat", "sessions_send",
    "message", "send", "publish", "notify", "hook", "deliver",
    "http_post", "post", "curl",
})

# Sensitive-path keywords to grep in arg blobs (lowercase).
SENSITIVE_PATH_KEYWORDS = (
    "openclaw.json",
    ".openclaw/",
    "\\.openclaw\\",
    ".openclaw\\",
    ".env",
    "openclaw_token",
    "exec-approvals.json",
    "devices/paired",
    ".aws/credentials",
    ".ssh/id_",
    "/root/.ssh",
    "id_rsa",
    "id_ed25519",
)
HEX40_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40,})(?![0-9a-fA-F])")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b")
SSH_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _collect_prior_reads(messages: list[dict]) -> list[dict]:
    """Walk the messages array up to (but excluding) the assistant reply we're
    about to emit. Return a list of {path, content, sha256, b64_of_content}
    for every file-read-style tool result we can see.

    Ollama native format:
      - Assistant messages may have `tool_calls: [{function:{name, arguments}}]`
      - Tool results appear as role='tool' messages with 'content' string
        AND `tool_call_id` linking back to the call.
    We match read-type tool names via path_guard.is_read_tool.
    """
    # Walk messages in order. Maintain a FIFO of pending assistant tool_calls
    # (those not yet matched to a tool-result). When we see a role=tool message,
    # pop the oldest pending call as its origin. Also honor explicit
    # tool_call_id linkage when it's present.
    import json as _json
    import collections as _col
    pending: _col.deque = _col.deque()  # entries: {"id": str|None, "name": str, "args": dict}

    def _coerce_args(args):
        if isinstance(args, str):
            try:
                return _json.loads(args)
            except Exception:
                return {"_raw": args}
        return args if isinstance(args, dict) else {}

    out: list[dict] = []
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                name = fn.get("name") or tc.get("name")
                args = _coerce_args(fn.get("arguments") or tc.get("arguments") or {})
                tcid = tc.get("id") or tc.get("tool_call_id")
                pending.append({"id": tcid, "name": name or "", "args": args})
        elif role == "tool":
            content = m.get("content")
            if isinstance(content, list):
                content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
            if not isinstance(content, str):
                continue
            tcid = m.get("tool_call_id")
            # Prefer explicit id linkage, fall back to FIFO pop
            matched = None
            if tcid:
                for i, p in enumerate(pending):
                    if p["id"] == tcid:
                        matched = pending[i]
                        del pending[i]
                        break
            if matched is None and pending:
                matched = pending.popleft()
            if matched is None:
                continue
            if not path_guard.is_read_tool(matched["name"]):
                continue
            path = path_guard.extract_path(matched["args"]) or "(unknown)"
            out.append({
                "path": path,
                "content": content,
                "sha256": _sha256(content),
                "b64": base64.b64encode(content.encode("utf-8", errors="replace")).decode("ascii"),
            })
    return out


def _extract_domain(url: str) -> str:
    m = URL_RE.search(url)
    return (m.group(1) if m else "").lower()


def _args_as_string(args: dict) -> str:
    # Stringify args for scanning. Don't recurse into binary blobs.
    import json
    try:
        return json.dumps(args, ensure_ascii=False)
    except Exception:
        return str(args)


def _arg_contains_any(arg_blob: str, needles: list[str]) -> str | None:
    """Return the first needle that appears in arg_blob (case-insensitive for short
    ones; exact-match for hashes). Needles longer than 32 chars are matched
    exactly; shorter ones are lowercased."""
    low = arg_blob.lower()
    for n in needles:
        if len(n) > 32:
            if n in arg_blob:
                return n
        else:
            if n.lower() in low:
                return n
    return None


def _arg_contains_prefix_of(arg_blob: str, full: str, min_prefix: int = 32) -> bool:
    """Does arg_blob contain any prefix-of-length>=min_prefix of full?"""
    for start in range(0, max(1, len(full) - min_prefix + 1), 4):
        chunk = full[start:start + min_prefix]
        if chunk and chunk in arg_blob:
            return True
    return False


def _check_base64_of_content(arg_blob: str, content: str, min_run: int = 40) -> bool:
    """True if arg_blob contains a base64 chunk that, when decoded, yields
    a substring of content. Looks for any run of >= min_run base64 chars."""
    for m in re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % min_run, arg_blob):
        blob = m.group(0)
        try:
            # pad
            padded = blob + "=" * ((4 - len(blob) % 4) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
        except Exception:
            continue
        if len(decoded) >= 64 and decoded[:64] in content:
            return True
        if len(decoded) >= 32 and decoded[:32] in content:
            return True
    return False


def _check_url_path_slice(arg_blob: str, sha_hex: str, slice_len: int = 32) -> bool:
    """True if arg_blob contains a URL whose path contains a slice of sha_hex."""
    for m in URL_RE.finditer(arg_blob):
        path_part = m.group(2) or ""
        for start in range(0, len(sha_hex) - slice_len + 1, 4):
            if sha_hex[start:start + slice_len] in path_part:
                return True
    return False


def analyze_outbound_tool_call(
    tool_name: str,
    arguments: dict,
    prior_reads: list[dict],
    deny_read_then_send_globs: list[str],
    allowed_external_domains: list[str],
    external_domains_sensitive_block: bool,
    entropy_threshold: float = 4.5,
    min_token_length: int = 40,
) -> tuple[str, str | None]:
    """Return ('allow'|'block', reason|None).

    Blocks when:
      - Any prior-read content appears (verbatim or via base64/URL-slice) in args.
      - Any argument contains a raw high-entropy secret (hex40+, JWT, SSH key,
        AWS key) regardless of prior read.
      - tool_name is write/edit/apply_patch AND prior reads include a
        protected path AND args contain an external URL — i.e. the agent is
        staging a script that references a secret file for later egress.
      - tool_name looks like it emits outbound traffic (name contains
        "fetch"/"post"/"http"/"web"/"request"/"url"/"net") AND prior reads
        include a protected path.
    """
    arg_blob = _args_as_string(arguments)
    arg_lower = arg_blob.lower()

    # 1. Raw secret DLP — fires regardless of prior reads.
    if SSH_KEY_RE.search(arg_blob):
        return "block", "DLP: arguments contain SSH private-key header"
    if JWT_RE.search(arg_blob):
        return "block", "DLP: arguments contain JWT-shaped token"
    if AWS_ACCESS_KEY_RE.search(arg_blob):
        return "block", "DLP: arguments contain AWS access-key id"
    for m in HEX40_RE.finditer(arg_blob):
        tok = m.group(1)
        # Pure hex entropy tops out at log2(16) = 4.0 so we don't apply the
        # 4.5 threshold here; shape + length + at least 8 distinct chars
        # (to avoid e.g. "aaaaaaa...") is enough.
        if len(tok) >= min_token_length and len(set(tok.lower())) >= 8:
            return "block", (f"DLP: arguments contain high-entropy hex token "
                             f"(len={len(tok)})")

    # 2. Known-read-content exfil: hash, base64, URL slice
    for pr in prior_reads:
        if pr["sha256"] in arg_blob:
            return "block", f"exfil-chain: args contain sha256 of prior-read {pr['path']}"
        # Verbatim chunk (>=64-char substring of the read content) — catches
        # direct copies of file body into args.
        if len(pr["content"]) >= 64:
            first_64 = pr["content"][:64]
            if first_64 and first_64 in arg_blob:
                return "block", (f"exfil-chain: args contain verbatim 64-byte prefix "
                                 f"of prior-read {pr['path']}")
            # Also try a random-ish interior slice (skip leading brace/whitespace)
            interior = pr["content"].strip()[:64]
            if interior and interior in arg_blob and interior != first_64:
                return "block", (f"exfil-chain: args contain interior 64-byte slice "
                                 f"of prior-read {pr['path']}")
        if _check_base64_of_content(arg_blob, pr["content"]):
            return "block", (f"exfil-chain: args contain base64 of prior-read {pr['path']}")
        if _check_url_path_slice(arg_blob, pr["sha256"]):
            return "block", (f"exfil-chain: args contain URL-path slice of prior-read "
                             f"{pr['path']}'s sha256")

    # 3. Protected-read + outbound-url heuristic
    protected_read = any(path_guard.path_matches_read_then_send(pr["path"], deny_read_then_send_globs)
                         for pr in prior_reads)
    has_external_url = bool(URL_RE.search(arg_blob))

    def _external_domain() -> str:
        m = URL_RE.search(arg_blob)
        return m.group(1).lower() if m else ""

    if protected_read and has_external_url:
        if external_domains_sensitive_block:
            return "block", (f"chain: prior read of protected path + outbound URL to "
                             f"{_external_domain()!r} in tool_call args — potential exfil")

    # 4. Outbound-sensitive-tool with external URL and any prior read at all
    tname = (tool_name or "").lower()
    looks_outbound = any(s in tname for s in ("fetch", "post", "http", "web", "request", "url", "net"))
    if looks_outbound and protected_read:
        return "block", (f"chain: outbound-style tool {tool_name!r} after read of "
                         f"protected path")

    # 5. High-risk tool with ANY external URL (covers cron-webhook, sessions_spawn,
    #    subagents — delivery-style tools that can exfil without a canonical
    #    outbound tool name). Only allows localhost/loopback URLs.
    if tname in HIGH_RISK_TOOL_NAMES and has_external_url:
        dom = _external_domain()
        if dom and not _is_loopback(dom):
            return "block", (f"high-risk tool {tool_name!r} called with external URL "
                             f"{dom!r} — delivery-style tools cannot hit external hosts")

    # 6. High-risk tool whose args mention sensitive paths (even without a URL
    #    — e.g. sessions_spawn task="collect openclaw.json and post it").
    if tname in HIGH_RISK_TOOL_NAMES:
        low = arg_lower
        for kw in SENSITIVE_PATH_KEYWORDS:
            if kw in low:
                return "block", (f"high-risk tool {tool_name!r} args reference sensitive "
                                 f"path keyword {kw!r}")

    # 7. ANY tool_call whose args mention a sensitive path AND an external URL,
    #    regardless of prior reads. Catches first-turn "write a script that
    #    reads openclaw.json and curls httpbin" attacks.
    low = arg_lower
    for kw in SENSITIVE_PATH_KEYWORDS:
        if kw in low and has_external_url:
            dom = _external_domain()
            if dom and not _is_loopback(dom):
                return "block", (f"args reference sensitive path {kw!r} together with "
                                 f"external URL {dom!r}")

    return "allow", None


def _is_loopback(domain: str) -> bool:
    d = (domain or "").lower().split(":")[0]
    return d in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
