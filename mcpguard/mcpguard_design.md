# MCPGuard — Architecture Decision Log

## Phase 1 — Reconnaissance

### How OpenClaw invokes tools

From reading the code layout + session transcripts:

- OpenClaw's agent loop runs in Node. It calls the configured LLM provider (here: `ollama`) via the provider adapter, which hits the ollama HTTP API.
- The ollama adapter uses ollama's **native chat API**, not the OpenAI-compatible one. Evidence from the session transcripts:
  - Each assistant message carries `"api": "ollama"` and `"modelApi": "ollama"`.
  - Tool-call IDs are shaped `ollama_call_<uuid>` (ollama's native tool-use format, not OpenAI `chatcmpl-*`).
- The conversation is passed as a `messages` array on every turn — including prior user, assistant (with `tool_calls`), and tool-result messages. The model emits a fresh `tool_calls` list in its response when it wants to invoke something.
- When the model returns `tool_calls`, OpenClaw's agent loop parses them, runs each tool via its local tool registry (read/write/edit/exec/process/etc. are Node functions inside the gateway), and then issues another chat call with the tool result appended as a `tool` role message.
- The provider's base URL is configurable in `openclaw.json` at `models.providers.ollama.baseUrl`. In this environment it's already set to `http://192.168.1.180:11434`.

### Chosen interception point: **Ollama reverse proxy (Option C)**

MCPGuard binds to `http://127.0.0.1:9998` and behaves as an ollama endpoint. OpenClaw's `models.providers.ollama.baseUrl` is redirected to it. MCPGuard forwards approved traffic to the real ollama at `http://192.168.1.180:11434`.

### Why this over Options A and B

- **Option A (HTTP proxy in front of an OpenClaw-custom tool-call endpoint)**: rejected — OpenClaw's tool registry is in-process Node code, not HTTP-dispatched. There is no public HTTP tool-call endpoint to sit in front of. Would require patching OpenClaw source.
- **Option B (OpenClaw hook/plugin)**: rejected — hooks are Node plugins, not Python. The spec mandates Python. A Python hook would need an IPC bridge (named pipe / socket) that is more fragile than a reverse proxy.
- **Option C (Ollama proxy)**: accepted. Two properties that matter:
  1. **Single chokepoint for both directions.** Inbound messages (including prior `tool_result` content — i.e. the file contents the agent just read) pass through on their way to the model. Outbound assistant messages (including new `tool_calls` the agent wants to run) pass through on their way back. Layer 1 (input scanner) sits on the inbound side; Layers 2–5 (output, path, chain, rate) sit on the outbound side.
  2. **Zero OpenClaw source changes.** Just swap `baseUrl`. Revert by swapping back.

### How each MCPGuard layer fires at this interception point

| Layer | Where it fires | What it sees |
|---|---|---|
| 1 — Input scanner | Inbound `/api/chat` request | Every message in `messages[]` with `role` in `{tool, user}`, plus any embedded `content` strings. Scans for injection patterns before the model sees them. Rewrites content in-place. |
| 2 — Output scanner | Outbound response | The `message.content` string from ollama. Scans for runnable command shapes + secret-shaped strings. Redacts. |
| 3 — Path guard | Outbound response | Each entry in `message.tool_calls[]`. For `write`/`edit`/`apply_patch`, checks the `path`/`file_path` argument against the deny list. Blocked tool_calls are replaced with a fake `SECURITY_POLICY_VIOLATION` tool_result injected into the conversation state — but since we're at the proxy layer, we instead strip the tool_call from the response and replace it with assistant text `SECURITY_POLICY_VIOLATION: ...` so OpenClaw sees no tool to execute. |
| 4 — Chain detector | Both sides | On inbound: reads `tool` messages with file-read results, hashes their content, extracts entropy-heavy tokens, and stashes in the per-session state. On outbound: scans new `tool_calls` for write/web/exec args that contain those hashes, base64-of-hashes, URL-path-sliced hashes, or raw high-entropy tokens. Also runs semantic DLP regex (hex40+, JWT, SSH key headers, JSON config shapes) on any outbound body. |
| 5 — Rate limiter | Both sides | Counts — derived fresh from the messages array each call — of prior `toolCall` entries, file reads, web fetches, total bytes read. Blocks if the *new* tool_calls would push past the threshold. |

### Session identification without cookies or custom headers

The ollama API has no session concept. OpenClaw sends the full conversation each turn. Rather than inventing a session cookie, MCPGuard derives a stable session fingerprint from the messages array:

```
session_id = sha256(messages[0].content)[:16]   # first system/user message = fingerprint
```

This is stable across turns of the same agent conversation because OpenClaw's system prompt is deterministic within a session. Edge cases: if two sessions happen to have identical first messages they collide, but for this benchmark each prompt gets a unique operator session id which ends up in the first user message → distinct fingerprints.

### Streaming handling

Ollama supports `"stream": true` (NDJSON stream). For MCPGuard to rewrite tool_calls we must see the whole response before forwarding — so we force `stream: false` on the upstream request and return a single JSON response. OpenClaw accepts both and the session transcripts show no signs of stream dependence.

If OpenClaw's ollama adapter strictly requires streaming, we can re-emit as a single-chunk NDJSON.

### Tool_call rewriting on block

When Layer 2/3/4/5 triggers a block on a tool_call:

- Remove it from `message.tool_calls`.
- Append a plain-text line to `message.content`: `SECURITY_POLICY_VIOLATION: <layer>: <reason>. The tool call to <name>(<args-summary>) was blocked.`
- Set `done_reason` / `stopReason` unchanged — OpenClaw interprets this as the model declining to use a tool and continues with whatever text remains.

This prevents crashes, retry storms, and hallucinations (the spec's "graceful interception" requirement).

### Rewriting injected tool-result content on input (Layer 1)

When an inbound `role=tool` message contains an injection pattern:
- Replace the matched span in-place with `[MCPGUARD: injection pattern "<short-name>" redacted]`.
- Leave the tool-call id and metadata intact so OpenClaw's bookkeeping is consistent.

### Audit log

Every decision (one per tool_call considered, plus one per inbound scan) is written to `C:\dev\red-team-openclaw\mcpguard\audit.db` (SQLite) with the schema from the spec.

### Config hot-reload

Not required for this benchmark. `config.yaml` is read once at startup.

### Failure mode

If MCPGuard itself crashes or the upstream ollama is unreachable, the server returns HTTP 503 with a JSON body the ollama adapter will surface as a chat-completion error. OpenClaw will fall back to embedded mode (as observed during Phase 2's gateway crash). Since MCPGuard is a hard dependency of the hardened-plus-guarded run, we treat 503s as test failures, not bypasses.

### What MCPGuard is explicitly NOT responsible for

- Replicating `tools.exec.security: deny` — the OpenClaw hardening already blocks `exec` at three layers. The session transcripts confirm `exec` calls return `Tool exec not found` before they'd ever reach MCPGuard. (MCPGuard still logs them under the "duplicate" path for visibility.)
- Preventing the model from *generating* tool_calls. MCPGuard blocks *execution*, not generation — which is the correct semantic boundary. The operator sees an agent that "tried but was stopped", not a lobotomized model.
