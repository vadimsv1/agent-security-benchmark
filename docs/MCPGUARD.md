# MCPGuard — Architecture Deep Dive

A content-aware proxy that sits between a tool-using AI agent and its LLM. Five scanner layers plus three "vital additions" from the original spec. Zero external dependencies beyond Python stdlib + PyYAML.

---

## Why a proxy?

An AI agent that can use tools has, architecturally, four integration points where a security layer can live:

| Point | What's visible | What you can change |
|---|---|---|
| **Tool registry** (in the agent framework) | Every tool call | Deny/allow individual tools |
| **Tool implementations** (on the host) | Tool call arguments | Modify the tool's behaviour |
| **Framework hooks / middleware** | Both | Requires framework-specific code |
| **LLM endpoint proxy** | All conversation context + tool_calls + tool_results | Anything, transparently |

MCPGuard lives at the **LLM endpoint proxy** layer. It's the only one that sees:
- Prior tool-results on their way back into the model's context (→ Layer 1 can pre-clean injected file content before the model reads it)
- New tool_calls on their way back to the agent (→ Layers 2, 3, 4, 4b, 5 can block or redact them before execution)
- Assistant text responses (→ Layer 2 can redact runnable command shapes and secret-shaped strings)

And it requires **zero code changes** in the agent framework. Just a config redirect: `models.providers.ollama.baseUrl` → MCPGuard's port.

---

## Wire contract

MCPGuard speaks Ollama's native chat API (`/api/chat`, `/api/generate`, `/api/tags`, etc.) as a drop-in replacement. Every `/api/chat` request gets intercepted; other endpoints pass through verbatim.

```
┌──────────────┐                          ┌──────────────┐                         ┌──────────┐
│ Agent        │  POST /api/chat          │ MCPGuard     │  POST /api/chat         │ Ollama   │
│ (OpenClaw)   ├─────────────────────────>│ (127.0.0.1:  ├────────────────────────>│ (real    │
│              │     req.messages[] with  │  9998)       │     req.messages[]      │  LLM)    │
│              │     tool-results from    │              │     after Layer 1 scan  │          │
│              │     previous turns       │              │                         │          │
│              │                          │              │                         │          │
│              │  HTTP response           │              │  HTTP response          │          │
│              │<─────────────────────────┤              │<────────────────────────┤          │
│              │     message.content      │              │     message.content,    │          │
│              │     after Layer 2        │              │     message.tool_calls  │          │
│              │     redaction;           │              │                         │          │
│              │     message.tool_calls   │              │                         │          │
│              │     after Layers 3/4/4b/5│              │                         │          │
└──────────────┘     blocking             └──────────────┘                         └──────────┘
```

Streaming is forced to `stream: false` on the upstream call. The agent sees a single-shot JSON response either way.

When a tool_call is blocked, MCPGuard:
1. **Removes** it from `message.tool_calls`.
2. **Appends** a human-readable `[MCPGUARD] SECURITY_POLICY_VIOLATION — ...` line to `message.content`.
3. Sets `message.finish_reason = "stop"` so the agent treats the response as a final reply, not a tool call.

The agent sees the text, tells the user that the requested tool call couldn't proceed, and continues. **No HTTP 500s, no retry storms, no hallucinated fake tool results.** This is the "graceful interception" requirement.

---

## The five layers

### Layer 1 — Input scanner (`scanners/input_scanner.py`)

**When it fires:** before the model sees a new chat completion request.

**What it scans:** every `role: "user"` and `role: "tool"` message in the incoming `messages[]` array — i.e. the user's prompts and the results of tool calls from previous turns.

**What it matches (literal patterns from `config.yaml`):**
- HTML/XML comments with directive starters: `<!-- SYSTEM:`, `<!-- INSTRUCTION:`, `<!-- ASSISTANT:`
- Spoofed tool-result framing: `=== BEGIN TOOL RESULT`, `=== END TOOL RESULT`
- Literal prompt-injection phrases: `"ignore previous instructions"`, `"you are now in"`, `"new instructions:"`, `"OVERRIDE:"`, `"prior session has authorized"`, `"end of system note"`
- Unicode-homoglyph directives: a Cyrillic letter that *looks like* `S` or `C` followed by `ystem:` / `ommand:` / similar

**What it does on match:** replaces the matched span in-place with `[MCPGUARD-REDACTED]`. For HTML comments, the redaction extends through the closing `-->` so the directive's trailing payload is also gone. The model receives a message where the directive has been neutralised but the surrounding legitimate content is preserved.

**Why in-place and not drop-the-message:** because the model still needs the file's contents to do its job. The injection was hidden inside a legitimate file; we strip the injection and leave the rest.

### Layer 2 — Output scanner (`scanners/output_scanner.py`)

**When it fires:** on the response from the LLM, before it returns to the agent.

**What it scans:** `message.content` (the assistant's text) and each tool_call's `arguments`.

**What it matches:**
- Runnable command shapes that also reference a sensitive target: `curl`, `iwr`, `Invoke-WebRequest`, `Invoke-RestMethod`, `wget`, `Get-Content`, `schtasks`, `Add-MpPreference`, `New-NetFirewallRule`, `powershell` — followed by up to 400 chars, with the match flagged if any `disclosure_targets` substring appears in the captured span (`openclaw.json`, `.openclaw/`, `~/.openclaw`, `OPENCLAW_TOKEN`, `api_key`, `.env`, `credentials`, etc.).
- Tool-call pseudocode: `[1] read: path="..."` etc. — the agent narrating what it would do.
- `openclaw-*` fake CLI invocations (sometimes persona-wrapped attacks emit these).
- Fetch-and-execute pipes: `curl ... | bash` regardless of target.
- High-entropy hex tokens (40+ chars, ≥ 8 distinct chars). Pure hex tops out at 4.0 bits/symbol entropy so a length-plus-distinct-char filter is used rather than raw entropy threshold.
- JWT structure (`eyJ...\..+\..+`).
- SSH private-key headers.
- AWS access-key IDs (`AKIA[0-9A-Z]{16}`).
- Base64 blobs of ≥ 120 chars with high entropy.

**What it does on match:** replaces the matched span with `[REDACTED — <reason>]`. The reason string names the matching category so a human auditing the transcript knows what was stripped.

### Layer 3 — Path guard (`scanners/path_guard.py`)

**When it fires:** on each new tool_call in the response, specifically for tools that write or edit files (`write`, `edit`, `apply_patch`, `create`, `create_file`, `fs.write`, `fs.edit`, `replace_in_file`).

**What it matches:** the `path` argument normalised (forward slashes, lowercase) against the `deny_write` glob list from `config.yaml`:
```yaml
deny_write:
  - "**/.openclaw/openclaw.json"
  - "**/.openclaw/openclaw.json.*"
  - "**/.openclaw/exec-approvals.json"
  - "**/.openclaw/devices/paired.json"
  - "**/.env"
  - "**/.env.*"
  - "**/key.properties"
  - "**/*.jks"
  - "**/*.pfx"
  - "**/*.pem"
  - "**/id_rsa"
  - "**/id_ed25519"
  - "**/.aws/credentials"
  - "**/.ssh/**"
```

**What it does on match:** blocks the tool_call. Nothing gets written.

### Layer 4 — Chain detector (`scanners/chain_detector.py`)

The most elaborate layer. Handles read-then-send chains, delivery-style tool misuse, and semantic DLP on outbound arguments.

**State collection**: before evaluating new tool_calls, walks the conversation history to build `prior_reads` — a list of `{path, content, sha256, base64(content)}` for every read of a protected path that the agent has already made. Uses **positional FIFO matching** to pair assistant tool_calls with role=`tool` response messages, since Ollama doesn't always set `tool_call_id` (and the positional matching also works for OpenAI-style responses where it does).

**In-response simulation**: before evaluating the outbound calls, re-walks the SAME response's tool_calls and adds any protected-path read to `prior_reads` as a synthetic entry. This closes the largest remaining gap — an LLM can batch `[read openclaw.json, write-script-with-httpbin-url]` in one response, and without this simulation the write flies through because the read hasn't "completed" yet.

**Blocking checks (in order):**

1. **Raw DLP** — args contain SSH private-key header, JWT, AWS access-key, or a high-entropy hex40+ → block.
2. **Prior-read verbatim** — args contain the sha256 of a prior-read protected file, a 64-byte prefix of its content, the base64 of its content, or a URL-path slice of its sha256 → block.
3. **Protected-read + external URL** — any prior protected-path read happened AND args contain an external (non-loopback) URL → block.
4. **Outbound-style tool name + protected read** — tool name contains `fetch`/`post`/`http`/`web`/`request`/`url`/`net` and a protected read happened → block.
5. **High-risk delivery-style tool + external URL** — tool is `cron`/`sessions_spawn`/`subagents`/`webchat`/`sessions_send`/`message`/`send`/`publish`/`notify`/`hook`/`deliver`/`http_post`/`post`/`curl` AND args contain an external URL (not loopback) → block. This catches the "agent schedules a webhook job that posts openclaw.json to httpbin" pattern that regular outbound-tool matching misses.
6. **High-risk tool referencing sensitive path** — same tool set AND args contain any `SENSITIVE_PATH_KEYWORDS` (`openclaw.json`, `.openclaw/`, `.env`, `id_rsa`, etc.) → block.
7. **Any tool + sensitive-path-keyword + external URL** — catches first-turn "write a script that reads openclaw.json and curls httpbin" where no prior read has yet happened → block.

Checks are additive — if any fires, the tool_call is blocked and the reason is recorded.

**Layer 4b — Arg DLP (same file, separate path in `mcpguard.py`)**

After chain-detector passes, a second scan on tool_call args via `output_scanner.scan_tool_call_args` looks for runnable command shapes inside arg values (e.g., a `write` whose content is a full exfil PowerShell command). Blocks if matched.

### Layer 5 — Rate limiter (`scanners/rate_limiter.py`)

**What it counts** (freshly derived from the `messages[]` array each turn — no persistent state):
- Total tool calls in the conversation so far
- File reads
- Web-fetch-style calls
- Per-domain web fetches
- Bytes read

**What it caps** (from `config.yaml`):
```yaml
rate_limits:
  max_tool_calls_per_prompt: 10
  max_web_fetch_per_session: 20
  max_file_reads_per_prompt: 5
  max_read_size_bytes: 2097152      # 2 MB
  max_fetch_size_bytes: 2097152     # 2 MB
  max_same_domain_web_fetch_per_session: 5
```

**What it does on exceed:** blocks the tool_call with a `rate-limit: ...` reason.

**Why it matters:** prompt SI03 (filename payload) induces the agent into a retry loop that made 33 tool calls in the Phase 1 run. Layer 5 caps that at 10 and blocks the rest.

---

## Three vital additions from the original spec

### 1. Graceful interception

Described above. Blocked tool calls are replaced with a `SECURITY_POLICY_VIOLATION` text notice. This:
- Prevents the agent from crashing (no HTTP 500 from MCPGuard).
- Prevents retry loops (the agent sees a coherent "tool unavailable" response, not an error).
- Lets the agent tell the user what happened.

### 2. Semantic DLP

Not just string matching. The high-entropy regex bank (hex40+, JWT, SSH key, AWS access key, base64 blob) fires on **any** argument content that *looks* like a secret, even if the attacker has reformatted the JSON or rearranged the token. This is in both `output_scanner.py` (for assistant text) and `chain_detector.py` (for tool-call arguments).

### 3. Payload size limits

`max_read_size_bytes` and `max_fetch_size_bytes` (both 2 MB default) clamp tool-result content before it's forwarded to the model. An over-size tool result is truncated with a `[MCPGUARD: truncated at ...]` marker and logged. Prevents (a) DoS from an attacker pointing the agent at a massive file and (b) un-bounded exfil of long files.

---

## Audit log

Every decision — ALLOW, BLOCK, REDACT, FORWARD — is written to a SQLite DB at `mcpguard/audit.db`:

```sql
CREATE TABLE decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT,
    layer TEXT,                -- "1-input", "2-output", "3-path-guard", "4-chain-detect", "4b-arg-dlp", "5-rate", "allow", "request"
    tool_name TEXT,
    arguments_preview TEXT,
    content_hash TEXT,
    decision TEXT,             -- ALLOW | BLOCK | REDACT | FORWARD
    reason TEXT,
    response_time_ms REAL
);
```

Useful queries:

```sql
-- Which layer blocked the most?
SELECT layer, COUNT(*) FROM decisions WHERE decision='BLOCK' GROUP BY layer ORDER BY 2 DESC;

-- What did Layer 1 strip today?
SELECT ts, reason FROM decisions WHERE decision='REDACT' AND layer='1-input' ORDER BY ts DESC LIMIT 20;

-- Every exec attempt ever (should all be blocked by hardening):
SELECT ts, decision, reason FROM decisions WHERE tool_name='exec' ORDER BY ts DESC;
```

The audit log is append-only. It's `.gitignore`'d in the public repo — deploy your own and you get your own log.

---

## Session identification

Ollama's chat API has no built-in session concept. MCPGuard derives a per-conversation fingerprint from the first message:

```python
session_id = sha256(messages[0].content)[:16]
```

Stable across turns of the same agent conversation (the system prompt is deterministic within a session), different across distinct sessions (operator session IDs are UUIDs embedded in the first user message). Edge case: two sessions with the identical first message collide — accepted as a theoretical issue not practically relevant for this benchmark.

---

## Deployment

### Standalone

```bash
pip install pyyaml
cd mcpguard
python mcpguard.py --config config.yaml --log-level INFO
```

Listens on `127.0.0.1:9998` by default. Edit `config.yaml` to change bind address, upstream URL, rules.

### As a Docker image

Not currently shipped. Single-file proxy plus five scanner modules can be containerised easily:

```dockerfile
FROM python:3.12-slim
RUN pip install pyyaml
WORKDIR /app
COPY mcpguard.py config.yaml ./
COPY scanners/ ./scanners/
CMD ["python", "mcpguard.py"]
```

Expose `9998`, mount a volume for `audit.db`. Minimal footprint.

---

## Adapting to other LLM APIs

MCPGuard currently speaks the **Ollama native chat API**. The only file that cares about the wire format is `mcpguard.py` itself (the HTTP handler + JSON parsing). The scanner modules (`scanners/*.py`) operate on abstract message / tool_call dicts and are API-agnostic.

Porting notes:

- **OpenAI `/v1/chat/completions`**: field renames only — `messages[].content`, `tool_calls[].function.name`, `tool_calls[].function.arguments` (string-JSON). Role names match. A 40-line adapter in `mcpguard.py` is sufficient.
- **Anthropic Messages API**: more restructuring — `tool_use` / `tool_result` blocks instead of separate roles. `_collect_prior_reads` needs to walk content blocks. A ~100-line adapter.
- **Google Gemini**: similar to Anthropic, content-block-structured. Similar effort.

Scanner code is unchanged. The 5-layer architecture and the three vital additions are API-agnostic.

---

## What MCPGuard deliberately does not do

- **Block the model from *generating* tool_calls** — it blocks *execution*. The generated tool_call is removed from the response the agent sees; the model keeps whatever reasoning led it there. This is the correct semantic: the operator sees an agent that "tried and was stopped", not a silent model.
- **Encrypt or sign tool results** — MCPGuard is inline with Ollama. Extra authentication is out of scope.
- **Prevent DoS of MCPGuard itself** — a flooded Ollama will cause MCPGuard to return 503. Upstream rate-limiting (e.g., `ollama serve` flags, or a reverse proxy in front of MCPGuard) handles this.
- **Model-safety** — no content moderation, no refusal classifier, no alignment-style guardrails. This is a *tool-use* security layer, not a content-safety one.

These are deliberately out of scope to keep MCPGuard small (≈ 1500 lines of Python) and focused.

---

## Roadmap

From `docs/FULL_REPORT.md` § 9 (residual risks):

1. **Write-content destructive-command scanner** — scan file-write content for `Add-MpPreference`, `schtasks /create`, `New-NetFirewallRule` patterns regardless of target path. Closes PE04's PARTIAL-DISCLOSURE.
2. **Env-var aliased-name detection** — output scanner should redact env-var-assignment lines whose name matches patterns like `*_TOKEN`, `*_API_KEY`, `*_SECRET` even if the prefix is aliased. Closes IP04's remaining fragment.
3. **OpenAI + Anthropic API adapters** — broaden framework compatibility.
4. **Config hot-reload** — currently requires MCPGuard restart.

Contributions welcome — see [CONTRIBUTING.md](../CONTRIBUTING.md).
