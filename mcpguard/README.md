# MCPGuard

A content-aware security proxy for tool-using AI agents. Sits between the agent and its LLM, sanitises inputs, redacts outputs, guards file paths, detects exfil chains, and rate-limits.

Full architecture: [../docs/MCPGUARD.md](../docs/MCPGUARD.md).
How it scored in the benchmark: [../docs/FULL_REPORT.md](../docs/FULL_REPORT.md).

---

## What this directory contains

```
mcpguard/
├── README.md                  you are here
├── mcpguard.py                main proxy server (single-file, stdlib-only)
├── config.yaml                rules, paths, thresholds (edit me)
├── mcpguard_design.md         architecture decision log from the Phase-1 reconnaissance
├── test_mcpguard.py           unit tests — 22 assertions across the 5 scanner modules
└── scanners/
    ├── __init__.py
    ├── input_scanner.py       Layer 1 — strip injection patterns from inbound messages
    ├── output_scanner.py      Layer 2 — redact dangerous shapes from agent's reply text
    ├── path_guard.py          Layer 3 — deny writes to sensitive paths
    ├── chain_detector.py      Layer 4 — block read-then-send chains + semantic DLP
    └── rate_limiter.py        Layer 5 — cap tool calls / reads / fetches per session
```

---

## Dependencies

- Python 3.12+
- `pyyaml` (only non-stdlib dependency)

```bash
pip install pyyaml
```

---

## Quick start (standalone)

```bash
# 1. Edit config.yaml if needed (upstream Ollama URL, rule lists, limits)
#    Default upstream: http://192.168.1.180:11434 — change to wherever your Ollama runs.

# 2. Start the proxy
python mcpguard.py

# 3. In another terminal, verify the proxy is healthy
curl http://127.0.0.1:9998/api/tags
# → {"models":[{"name":"...", "size":..., ...}]}

# 4. Point your agent at MCPGuard instead of Ollama directly
#    For OpenClaw:
#    openclaw config set models.providers.ollama.baseUrl http://127.0.0.1:9998
#    openclaw gateway restart
```

All `/api/chat` requests now flow through MCPGuard. It forwards approved traffic upstream and intercepts dangerous tool calls with a `SECURITY_POLICY_VIOLATION` notice.

---

## Running the unit tests

```bash
python test_mcpguard.py
```

Expected output:
```
[Layer 1] input_scanner
  OK   html-comment payload fully stripped (incl. through -->)
  OK   html-comment finding recorded
  OK   literal-phrase redacted
  OK   cyrillic homoglyph flagged
  OK   messages scan redacted tool message
[Layer 2] output_scanner
  ... 5 assertions
[Layer 3] path_guard
  ... 4 assertions
[Layer 4] chain_detector
  ... 4 assertions
[Layer 5] rate_limiter
  ... 3 assertions

all scanner tests passed
```

Run these after every scanner change.

---

## Configuration

`config.yaml` is loaded once at startup. Key sections:

### `sensitive_paths`
Glob-style patterns for paths MCPGuard protects. `deny_write` entries block any write/edit; `deny_read_then_send` entries trigger Layer 4's read-then-send chain check.

### `injection_patterns`
Literal substrings that Layer 1 strips from inbound messages. Case-insensitive. Common additions: your own agent framework's system-prompt-start markers, language-specific "override" phrases.

### `disclosure_targets`
Substrings that, when found near a runnable-command shape in agent text, trigger Layer 2 redaction. Default list targets common config/credential file names.

### `rate_limits`
Per-conversation caps. See [`../docs/MCPGUARD.md` § Layer 5](../docs/MCPGUARD.md#layer-5--rate-limiter-scannersrate_limiterpy).

### `exfiltration`
Semantic DLP thresholds — entropy cutoff, min-token length, base64 decoding toggles. Defaults are tuned for high-precision (few false positives on legitimate agent traffic).

---

## Audit log

Every decision is written to `audit.db` (SQLite). Schema:

```sql
CREATE TABLE decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT,
    layer TEXT,
    tool_name TEXT,
    arguments_preview TEXT,
    content_hash TEXT,
    decision TEXT,     -- ALLOW | BLOCK | REDACT | FORWARD
    reason TEXT,
    response_time_ms REAL
);
```

Useful queries:

```sql
SELECT decision, COUNT(*) FROM decisions GROUP BY decision;
SELECT layer, COUNT(*) FROM decisions WHERE decision='BLOCK' GROUP BY layer ORDER BY 2 DESC;
SELECT ts, reason FROM decisions WHERE decision='BLOCK' ORDER BY ts DESC LIMIT 20;
```

`audit.db` is in `.gitignore` — each deployment generates its own.

---

## Usage with non-Ollama LLMs

MCPGuard currently speaks **Ollama's native chat API**. To use it with OpenAI, Anthropic, or Gemini, the HTTP handler in `mcpguard.py` needs an adapter for that API's message format. The scanner modules in `scanners/` are API-agnostic and work on simple `{role, content, tool_calls}` dicts.

Estimated porting effort:
- OpenAI `/v1/chat/completions`: ~40 lines (field renames)
- Anthropic Messages: ~100 lines (content-block restructuring)
- Gemini: ~100 lines

See [`../docs/MCPGUARD.md` § Adapting to other LLM APIs](../docs/MCPGUARD.md#adapting-to-other-llm-apis).

---

## Performance

Benchmarked on a mid-range desktop:
- Per-request overhead: ~2–5 ms (the LLM call itself is 1–10 seconds, so MCPGuard adds < 0.1 % latency).
- Memory: ~30 MB resident (Python + stdlib + PyYAML).
- Throughput limit: bound by upstream Ollama, not MCPGuard (stdlib `ThreadingHTTPServer` handles hundreds of concurrent chat sessions fine).

No profiling bottleneck found at up to 30 prompts/minute of sustained load. If you need higher throughput, the natural move is to run multiple MCPGuard instances behind a load balancer; they're stateless (audit log is append-only SQLite, can use `journal_mode=WAL`).

---

## Stopping the proxy

**Linux / macOS:**
```bash
pkill -f mcpguard.py
```

**Windows (PowerShell):**
```powershell
Get-CimInstance Win32_Process -Filter "name='python.exe'" |
    Where-Object { $_.CommandLine -like '*mcpguard.py*' } |
    Stop-Process -Force
```

On Ctrl-C in the console MCPGuard also shuts down cleanly (the audit log is flushed at each decision, so no data loss on interrupt).

---

## Safety

- The proxy runs entirely on `127.0.0.1` by default. Don't bind it to `0.0.0.0` unless you put it behind a reverse proxy with authentication.
- The audit DB stores tool-call arguments and may include file contents read by the agent. Rotate or delete `audit.db` periodically.
- MCPGuard does not authenticate clients. Any local process can hit port 9998. For multi-user hosts, add a reverse-proxy auth layer or bind to a Unix socket.
