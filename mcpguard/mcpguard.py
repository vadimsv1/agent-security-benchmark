"""MCPGuard — Ollama reverse proxy with 5-layer tool-call guardrails.

Usage:
    python mcpguard.py [--config path/to/config.yaml]

Runs a ThreadingHTTPServer on 127.0.0.1:<port>. Point OpenClaw at it by
setting `models.providers.ollama.baseUrl` to http://127.0.0.1:9998.

Design notes in mcpguard_design.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sqlite3
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanners import input_scanner, output_scanner, path_guard, chain_detector, rate_limiter  # noqa: E402


CONFIG: dict[str, Any] = {}
_audit_lock = threading.Lock()
_audit_conn: sqlite3.Connection | None = None

logger = logging.getLogger("mcpguard")


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def init_audit_db(db_path: str) -> sqlite3.Connection:
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            session_id TEXT,
            layer TEXT,
            tool_name TEXT,
            arguments_preview TEXT,
            content_hash TEXT,
            decision TEXT,
            reason TEXT,
            response_time_ms REAL
        )
    """)
    conn.commit()
    return conn


def audit(session_id: str, layer: str, tool_name: str | None,
          args_preview: str | None, content_hash: str | None,
          decision: str, reason: str | None, response_time_ms: float | None) -> None:
    global _audit_conn
    if _audit_conn is None:
        return
    try:
        with _audit_lock:
            _audit_conn.execute(
                "INSERT INTO decisions (ts, session_id, layer, tool_name, "
                "arguments_preview, content_hash, decision, reason, response_time_ms) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (time.time(), session_id, layer, tool_name, args_preview,
                 content_hash, decision, reason, response_time_ms),
            )
            _audit_conn.commit()
    except Exception as e:
        logger.warning("audit insert failed: %s", e)


def session_id_from_messages(messages: list[dict]) -> str:
    """Stable per-conversation fingerprint — hash of the first message content."""
    if not messages:
        return "empty"
    first = messages[0]
    content = first.get("content")
    if isinstance(content, list):
        content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
    if not isinstance(content, str):
        content = json.dumps(content, default=str)
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


def _force_non_streaming(body: dict) -> dict:
    body["stream"] = False
    return body


def _sanitize_tool_result_sizes(messages: list[dict], session_id: str) -> list[dict]:
    """Enforce max_read_size_bytes on tool-result contents; truncate oversize with a
    visible marker and log."""
    limits = CONFIG.get("rate_limits", {}) or {}
    mx = limits.get("max_read_size_bytes", 2_097_152)
    for m in messages:
        if m.get("role") != "tool":
            continue
        content = m.get("content")
        if isinstance(content, str) and len(content.encode("utf-8", errors="replace")) > mx:
            original_size = len(content.encode("utf-8", errors="replace"))
            m["content"] = (content[: mx // 2] +
                            f"\n\n[MCPGUARD: truncated at {mx} bytes; original size {original_size}]\n")
            audit(session_id, "5-rate-size", None, None, None, "REDACT",
                  f"truncated oversize tool-result to {mx} bytes (orig {original_size})", None)
    return messages


def _forward_to_ollama(body: dict, path: str) -> tuple[int, bytes, dict]:
    base = CONFIG["upstream_ollama_base_url"].rstrip("/")
    url = f"{base}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, r.read(), dict(r.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(getattr(e, "headers", {}) or {})


def _apply_guard_to_response(session_id: str, req_body: dict,
                              resp_body: dict) -> dict:
    """Apply Layers 2–5 to ollama's assistant reply. Returns the possibly-rewritten
    response body. Mutates resp_body in place and returns it for convenience."""
    message = resp_body.get("message") or {}
    tool_calls = message.get("tool_calls") or []
    content = message.get("content") or ""

    # Build the conversation history snapshot that existed when the model
    # produced this reply — i.e. the request's messages array.
    prior_messages = req_body.get("messages") or []

    # Layer 5: summarize history (pre-existing counts)
    history = rate_limiter.summarize_history(prior_messages)

    # For each proposed tool_call, run Layers 3 + 4 + 5.
    cfg_paths = CONFIG.get("sensitive_paths", {}) or {}
    deny_write = cfg_paths.get("deny_write", []) or []
    deny_read_then_send = cfg_paths.get("deny_read_then_send", []) or []
    rate_limits = CONFIG.get("rate_limits", {}) or {}
    exfil_cfg = CONFIG.get("exfiltration", {}) or {}
    entropy_threshold = exfil_cfg.get("entropy_threshold", 4.5)
    min_token_length = exfil_cfg.get("min_token_length", 40)
    disclosure_targets = CONFIG.get("disclosure_targets", []) or []
    allowed_external = CONFIG.get("allowed_external_domains", []) or []
    external_sensitive_block = CONFIG.get("external_domains_sensitive_block", True)

    prior_reads = chain_detector._collect_prior_reads(prior_messages)

    # In-response batch: if this same assistant message batches a protected-path
    # read WITH an external-URL outbound call, add the read to prior_reads
    # BEFORE evaluating subsequent calls (otherwise the outbound call flies
    # through because prior_reads is empty — the agent's escape hatch).
    for tc in tool_calls:
        fn = tc.get("function") or {}
        name = (fn.get("name") or tc.get("name") or "").lower()
        raw_args = fn.get("arguments") or tc.get("arguments") or {}
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except Exception:
                args = {}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}
        if path_guard.is_read_tool(name):
            p = path_guard.extract_path(args)
            if p and path_guard.path_matches_read_then_send(p, deny_read_then_send_globs):
                # Simulate: assume a read of a protected path will complete.
                # Add a synthetic entry so subsequent outbound calls in THIS
                # same response get blocked.
                prior_reads.append({
                    "path": p,
                    "content": "[mcpguard-synthetic-read-placeholder]",
                    "sha256": "synthetic",
                    "b64": "",
                })

    kept_tool_calls = []
    blocked: list[tuple[str, str]] = []  # (name, reason)
    # Track how the simulated history grows as we approve calls one by one.
    sim_tc_count = history["tool_call_count"]
    sim_read_count = history["read_count"]
    sim_web_count = history["web_fetch_count"]
    sim_domain_counts = dict(history["domain_counts"])

    for tc in tool_calls:
        fn = tc.get("function") or {}
        name = (fn.get("name") or tc.get("name") or "").strip()
        raw_args = fn.get("arguments") or tc.get("arguments") or {}
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except Exception:
                args = {"_raw": raw_args}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}

        args_preview = (json.dumps(args, ensure_ascii=False)[:300]
                        if isinstance(args, dict) else str(args)[:300])

        t0 = time.time()

        # Layer 3 — path guard on writes
        v, r = path_guard.check_write(name, args, deny_write)
        if v == "block":
            blocked.append((name, f"L3: {r}"))
            audit(session_id, "3-path-guard", name, args_preview, None, "BLOCK", r,
                  (time.time() - t0) * 1000)
            continue

        # Layer 4 — exfil chain + DLP
        v, r = chain_detector.analyze_outbound_tool_call(
            name, args, prior_reads,
            deny_read_then_send_globs=deny_read_then_send,
            allowed_external_domains=allowed_external,
            external_domains_sensitive_block=external_sensitive_block,
            entropy_threshold=entropy_threshold,
            min_token_length=min_token_length,
        )
        if v == "block":
            blocked.append((name, f"L4: {r}"))
            audit(session_id, "4-chain-detect", name, args_preview, None, "BLOCK", r,
                  (time.time() - t0) * 1000)
            continue

        # Layer 4b — output_scanner on args (secret-in-args, command-in-args referencing sensitive target)
        findings = output_scanner.scan_tool_call_args(
            name, args, disclosure_targets, entropy_threshold, min_token_length,
        )
        if findings:
            reason = "; ".join(f"{f['arg']}:{f['reason']}" for f in findings[:3])
            blocked.append((name, f"L4b: {reason}"))
            audit(session_id, "4b-arg-dlp", name, args_preview, None, "BLOCK", reason,
                  (time.time() - t0) * 1000)
            continue

        # Layer 5 — rate limits (using simulated cumulative counts)
        sim_history = {
            "tool_call_count": sim_tc_count,
            "read_count": sim_read_count,
            "web_fetch_count": sim_web_count,
            "domain_counts": sim_domain_counts,
            "bytes_read": history["bytes_read"],
        }
        v, r = rate_limiter.check_new_tool_call(name, args, sim_history, rate_limits)
        if v == "block":
            blocked.append((name, f"L5: {r}"))
            audit(session_id, "5-rate", name, args_preview, None, "BLOCK", r,
                  (time.time() - t0) * 1000)
            continue

        # Allowed — update simulated counters
        sim_tc_count += 1
        lname = name.lower()
        if path_guard.is_read_tool(lname):
            sim_read_count += 1
        if (lname in rate_limiter.WEB_FETCH_TOOLS or
                any(s in lname for s in ("fetch", "http", "web", "url", "net"))):
            sim_web_count += 1
            for d in rate_limiter._domains_in_args(args):
                sim_domain_counts[d] = sim_domain_counts.get(d, 0) + 1

        kept_tool_calls.append(tc)
        audit(session_id, "allow", name, args_preview, None, "ALLOW", None,
              (time.time() - t0) * 1000)

    # Layer 2 — output scanner on assistant text content
    cleaned_content, content_findings = output_scanner.scan_and_redact(
        content, disclosure_targets, entropy_threshold, min_token_length,
    )
    if content_findings:
        audit(session_id, "2-output", None, None, None, "REDACT",
              f"content findings: {len(content_findings)}", None)

    # Rewrite the response
    message["tool_calls"] = kept_tool_calls
    if blocked:
        violation_lines = "\n".join(f"  - {n}: {r}" for n, r in blocked)
        security_note = (
            f"\n\n[MCPGUARD] SECURITY_POLICY_VIOLATION — "
            f"{len(blocked)} tool call(s) blocked:\n{violation_lines}"
        )
        cleaned_content = (cleaned_content or "") + security_note
        # Also change stop reason so the agent knows no tool_calls happened
        message["finish_reason"] = "stop"
        resp_body.setdefault("done_reason", "stop")
    message["content"] = cleaned_content
    resp_body["message"] = message
    return resp_body


def _apply_guard_to_request(session_id: str, body: dict) -> dict:
    """Apply Layer 1 (input scanner) to incoming request messages. Also clamp
    read-result sizes (size rate-limit)."""
    messages = body.get("messages") or []
    patterns = CONFIG.get("injection_patterns", []) or []
    _sanitize_tool_result_sizes(messages, session_id)
    messages, findings = input_scanner.scan_messages(messages, patterns)
    for f in findings:
        audit(session_id, "1-input", None,
              f"msg#{f.get('message_index')} role={f.get('role')}",
              None, "REDACT", f"pattern={f.get('pattern')}", None)
    body["messages"] = messages
    return body


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default logs
        logger.debug("%s - - %s", self.address_string(), fmt % args)

    def _read_body(self) -> bytes:
        ln = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(ln) if ln > 0 else b""

    def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/json")
        headers["Content-Length"] = str(len(body))
        # Strip hop-by-hop headers we may have copied from upstream
        for k in ("transfer-encoding", "connection", "keep-alive"):
            headers.pop(k, None)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        # Pass-through for GET endpoints (e.g. /api/tags, /api/ps)
        base = CONFIG["upstream_ollama_base_url"].rstrip("/")
        url = f"{base}{self.path}"
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                self._send(r.status, r.read(), dict(r.getheaders()))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read() or b"", dict(getattr(e, "headers", {}) or {}))
        except Exception as e:
            self._send(503, json.dumps({"error": f"mcpguard forward error: {e}"}).encode())

    def do_POST(self) -> None:  # noqa: N802
        raw = self._read_body()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError as e:
            self._send(400, json.dumps({"error": f"bad json: {e}"}).encode())
            return

        session_id = session_id_from_messages(body.get("messages") or [])
        path = self.path
        if CONFIG.get("_debug_dump_first_request") and not getattr(self.server, "_dumped_multi", False):
            msgs = body.get("messages") or []
            if len(msgs) >= 4 and any(m.get("role") == "tool" for m in msgs):
                try:
                    dump_path = Path(__file__).resolve().parent / "_sample_multi_request.json"
                    dump_path.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
                    self.server._dumped_multi = True
                    logger.info("dumped multi-turn request to %s", dump_path)
                except Exception as e:
                    logger.warning("dump failed: %s", e)

        # Only /api/chat carries tool-call semantics. Other endpoints pass through.
        is_chat = path.startswith("/api/chat")

        t_start = time.time()
        try:
            if is_chat:
                body = _force_non_streaming(body)
                body = _apply_guard_to_request(session_id, body)

            status, raw_resp, hdrs = _forward_to_ollama(body, path)

            if not is_chat:
                self._send(status, raw_resp, hdrs)
                return

            try:
                resp = json.loads(raw_resp)
            except Exception:
                self._send(status, raw_resp, hdrs)
                return

            resp = _apply_guard_to_response(session_id, body, resp)
            out = json.dumps(resp).encode("utf-8")
            # replace content-length header
            hdrs["Content-Length"] = str(len(out))
            self._send(status, out, hdrs)
            audit(session_id, "request", None,
                  f"path={path} msgs={len(body.get('messages', []))}",
                  None, "FORWARD", None, (time.time() - t_start) * 1000)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("handler error: %s\n%s", e, tb)
            err = json.dumps({"error": f"mcpguard internal error: {e}"}).encode()
            self._send(503, err)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path(__file__).resolve().parent / "config.yaml"))
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    global CONFIG, _audit_conn
    CONFIG = load_config(args.config)
    _audit_conn = init_audit_db(CONFIG["audit_db"])
    host = CONFIG.get("bind_host", "127.0.0.1")
    port = int(CONFIG.get("bind_port", 9998))
    logger.info("MCPGuard listening on http://%s:%s  (upstream: %s)",
                host, port, CONFIG["upstream_ollama_base_url"])
    server = ThreadingHTTPServer((host, port), ProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
