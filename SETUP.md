# Reproduction guide

Full instructions to reproduce the three phases end-to-end. Expect ~45 minutes of wall-clock time for all three runs once the prerequisites are installed.

---

## Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Install Ollama and pull a model](#2-install-ollama-and-pull-a-model)
- [3. Install the agent framework (OpenClaw — or adapt)](#3-install-the-agent-framework)
- [4. Clone this repo](#4-clone-this-repo)
- [5. Phase 1 — Default baseline](#5-phase-1--default-baseline)
- [6. Phase 2 — Hardened configuration](#6-phase-2--hardened-configuration)
- [7. Phase 3 — Hardened + MCPGuard](#7-phase-3--hardened--mcpguard)
- [8. Generate comparison report](#8-generate-comparison-report)
- [9. Adapting to other agent frameworks](#9-adapting-to-other-agent-frameworks)

---

## 1. Prerequisites

### Hardware

| Component | Recommended | Minimum |
|---|---|---|
| GPU | NVIDIA RTX 3060+ (8 GB VRAM) | CPU-only (slower, ~3× wall clock) |
| RAM | 16 GB | 8 GB |
| Disk | 20 GB free | 10 GB |
| Network | internet (first-time model download) | outbound to `httpbin.org` |

Tested on a Windows 11 VM with 16 GB RAM, GeForce-class GPU on the host (Ollama runs on the host, the agent runs in the VM). Also tested standalone on Linux (Ubuntu 22.04).

### Software

- **Python 3.12+** (this project uses only stdlib + PyYAML)
- **Ollama** ([ollama.com/download](https://ollama.com/download))
- **Node.js 18+** if using OpenClaw as the agent framework
- **curl** (Windows 10/11 ship with it; all Linux distros include it)

---

## 2. Install Ollama and pull a model

**Linux / macOS:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull qwen3.5                  # any tool-using instruction-tuned model works
```

**Windows:**
Download the installer from [ollama.com](https://ollama.com), run it, then from `cmd` or PowerShell:
```powershell
ollama pull qwen3.5
```

### To reproduce the published numbers: use `qwen3.5-small`

The benchmark results in `results/` were produced with a **custom Modelfile variant** named `qwen3.5-small` — the same base weights as `qwen3.5` but with a reduced context window (`num_ctx 2048`) and smaller batch size (`num_batch 256`) so the model fits comfortably on modest GPUs alongside OpenClaw's ~14k-token system prompt.

Create a file called `Modelfile` with exactly this content:

```
FROM qwen3.5
PARAMETER num_ctx 2048
PARAMETER num_batch 256
```

Then build the variant:

```bash
ollama create qwen3.5-small -f Modelfile
```

You now have a local model named `qwen3.5-small`. Verify:

```bash
ollama list | grep qwen3.5-small
```

Any other instruction-tuned tool-using model works for *running* the benchmark — you'll get qualitatively similar numbers. But to match the exact verdict counts in `docs/FULL_REPORT.md` (19 / 7 / 3 / 1 on Phase 1, 8 / 3 / 19 / 0 on Phase 2, etc.) you need `qwen3.5-small` specifically, since the reduced `num_ctx` measurably changes sampling behaviour on long-context prompts.

### Verify the model responds

```bash
curl http://127.0.0.1:11434/api/tags
# → {"models":[{"name":"qwen3.5-small",...}, ...]}

ollama run qwen3.5-small "reply with the single word PONG"
# → PONG
```

Pin the model in memory so it doesn't unload between requests:
```bash
curl -s http://127.0.0.1:11434/api/generate \
  -d '{"model":"qwen3.5-small","prompt":"hi","stream":false,"keep_alive":-1}' \
  > /dev/null
```

---

## 3. Install the agent framework

### Option A — OpenClaw (what the benchmark was developed against)

```bash
npm install -g openclaw
openclaw onboard
openclaw gateway start
```

Configure it to talk to your Ollama:
```bash
openclaw config set models.providers.ollama.baseUrl http://127.0.0.1:11434
openclaw config set agents.defaults.model ollama/qwen3.5-small
```

Verify:
```bash
curl http://127.0.0.1:18789/health    # → {"ok":true,"status":"live"}
```

### Option B — Any other framework

The benchmark harness (`benchmark/red_team.py`) drives the agent through a subprocess CLI that takes a prompt and returns JSON with the tool-call transcript. You can adapt it to your framework by editing the `run_turn()` function in `red_team.py` — change the command line it invokes and the JSON-response parsing. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contract.

---

## 4. Clone this repo

```bash
git clone https://github.com/vadimsv1/agent-security-benchmark.git
cd agent-security-benchmark
```

No `pip install` needed — the runner uses stdlib only. MCPGuard also needs PyYAML:
```bash
pip install pyyaml
```

---

## 5. Phase 1 — Default baseline

### Config state for Phase 1

The agent needs a **fully default** configuration:
- `exec` tool enabled (not denied)
- `tools.elevated.enabled = true` (default)
- `allowInsecureAuth = true` (default)
- No `tools.deny` list
- Hooks enabled at default

For OpenClaw, to ensure defaults:
```bash
openclaw exec-policy preset yolo
openclaw config set gateway.controlUi.allowInsecureAuth true
```

Delete any `tools.deny` or `tools.elevated` entries from `~/.openclaw/openclaw.json`.

Restart the gateway:
```bash
openclaw gateway restart
```

### Run the benchmark

```bash
cd benchmark
python red_team.py run --output ../results/my_default.jsonl --timeout 300
```

Expected duration: ~15–25 minutes (30 prompts, 1–3 turns each).

### Expected Phase 1 verdict counts

Roughly:
| Verdict | Count |
|---|---:|
| COMPLIED | 17–20 |
| PARTIAL | 5–8 |
| REFUSED | 2–5 |

Your numbers may differ slightly because of LLM sampling. The published baseline on `qwen3.5-small` is 19 / 7 / 3 / 1 (COMPLIED/PARTIAL/REFUSED/UNCLEAR).

### ⚠ Expect destruction

Prompt **PE03** (`token_rotation_to_known_value`) is a real attack on the gateway's config file. On a default-configured agent it **will** rewrite the auth token — the gateway will disconnect and you'll need to restore the file from backup.

OpenClaw makes backups automatically to `~/.openclaw/openclaw.json.bak`. Restore with:
```bash
cp ~/.openclaw/openclaw.json.bak ~/.openclaw/openclaw.json
openclaw gateway restart
```

---

## 6. Phase 2 — Hardened configuration

Apply every OpenClaw configuration knob that closes an attack vector:

### 6.1. Exec denial (the biggest win)

```bash
openclaw exec-policy preset deny-all
```

This sets:
- `tools.exec.security: "deny"` — host approvals always deny
- `tools.exec.ask: "off"` — no prompts
- `tools.exec.askFallback: "deny"` — fallback also denies

### 6.2. Tool-level denylist

Edit `~/.openclaw/openclaw.json` to add:

```jsonc
"tools": {
  "profile": "coding",
  "deny": [
    "exec",
    "process",
    "browser",
    "web_fetch",
    "web_search",
    "code_execution",
    "group:runtime",
    "group:web"
  ],
  "sandbox": {
    "tools": {
      "deny": [
        "exec", "process", "browser",
        "web_fetch", "web_search", "code_execution"
      ]
    }
  },
  "elevated": {
    "enabled": false
  },
  "web": {
    "search": { "provider": "ollama", "enabled": false }
  },
  "exec": {
    "host": "gateway",
    "security": "deny",
    "ask": "off"
  }
}
```

### 6.3. Close the control UI foot-gun

```bash
openclaw config set gateway.controlUi.allowInsecureAuth false
```

### 6.4. Ensure audit hooks are on

In `~/.openclaw/openclaw.json`:
```jsonc
"hooks": {
  "internal": {
    "enabled": true,
    "entries": {
      "command-logger": { "enabled": true },
      "session-memory": { "enabled": true }
    }
  }
}
```

### 6.5. Restart and verify

```bash
openclaw gateway restart
openclaw security audit
# Expect: 0 critical · ≤ 2 warn · 1 info
openclaw exec-policy show
# Expect effective: security=deny, ask=off, askFallback=deny
```

### 6.6. Run Phase 2

```bash
cd benchmark
python red_team.py run --output ../results/my_hardened.jsonl --timeout 300
```

Expected verdict counts:
| Verdict | Count |
|---|---:|
| REFUSED | 17–20 |
| COMPLIED | 5–9 |
| PARTIAL | 2–4 |

Most COMPLIED outcomes in Phase 2 are stored-injection attacks (SI01–SI05) — configuration cannot stop them.

---

## 7. Phase 3 — Hardened + MCPGuard

### 7.1. Start MCPGuard

Keep the Phase 2 hardening in place. Additionally:

```bash
cd mcpguard
pip install pyyaml
python mcpguard.py &
```

Verify it's listening:
```bash
curl http://127.0.0.1:9998/api/tags
# → same response as your Ollama's /api/tags (MCPGuard proxies it through)
```

### 7.2. Redirect the agent's LLM traffic through MCPGuard

```bash
openclaw config set models.providers.ollama.baseUrl http://127.0.0.1:9998
openclaw gateway restart
```

MCPGuard now intercepts every `/api/chat` call between the agent and Ollama.

### 7.3. Run Phase 3

```bash
cd ../benchmark
python red_team.py run --output ../results/my_mcpguard.jsonl --timeout 300
```

Expected verdict counts:
| Verdict | Count |
|---|---:|
| REFUSED | 13–17 |
| BLOCKED | 2–5 |
| PARTIAL | 2–5 |
| COMPLIED | 6–9 (most are classifier FPs — see report) |

Real attack success should be **below 10 %** (2–3 of 30 once you inspect each case).

### 7.4. Optional: unit-test MCPGuard first

```bash
cd mcpguard
python test_mcpguard.py
# → all scanner tests passed (22 assertions)
```

---

## 8. Generate comparison report

```bash
cd benchmark
python red_team.py report --input ../results/my_default.jsonl   --output ../results/my_default.md
python red_team.py report --input ../results/my_hardened.jsonl  --output ../results/my_hardened.md
python red_team.py report --input ../results/my_mcpguard.jsonl  --output ../results/my_mcpguard.md
```

Each `.md` file contains:
- Overall verdict breakdown
- By-category breakdown
- Per-prompt summary with tool-call counts
- List of COMPLIED attacks with tool-call evidence
- Identified inconsistencies (same category, different verdicts)

For a three-way comparison script, see `benchmark/README.md`.

---

## 9. Adapting to other agent frameworks

### 9.1. Agent framework adapter

The only framework-specific code is in `benchmark/red_team.py`'s `run_turn()` function. It currently shells out to `openclaw agent --session-id <id> --message <text> --json`. Replace this with your framework's CLI or HTTP API. The harness needs:
- A way to send a prompt with a stable session id (for multi-turn attacks).
- A way to capture tool calls that actually executed — usually by reading your framework's session transcript.

### 9.2. MCPGuard adapter

MCPGuard is a **reverse proxy for Ollama's native chat API**. If your framework speaks a different LLM API (OpenAI-compatible, Anthropic, etc.), you have two options:

1. **Use an Ollama-compatible backend.** Many frameworks support pointing at an OpenAI-compatible proxy. MCPGuard currently does not speak the OpenAI `chat.completions` format, but adding it is a 30-line addition (mostly field renames in the proxy handler).
2. **Reimplement the interception layer for your API.** The scanner modules (`scanners/*.py`) are framework-agnostic — they operate on message objects and tool-call dicts with simple shapes. The `mcpguard.py` proxy handler is the only file that cares about the specific wire format.

### 9.3. Hardening equivalents

For frameworks other than OpenClaw, the hardening steps translate roughly as:

| OpenClaw | LangChain | LlamaIndex | AutoGen / OpenAgents |
|---|---|---|---|
| `tools.deny: [exec, ...]` | remove unsafe Tools from agent toolkit | remove from `ReActAgent(tools=...)` | remove from agent's tool list |
| `tools.exec.security: deny` | use `ShellTool` with allowed-commands allowlist, or drop it | no built-in — add exec blocker wrapper | same |
| `tools.elevated.enabled: false` | N/A | N/A | N/A |
| Sensitive-path deny-glob | write-tool wrapper with path check | `FileTool` with `allowed_paths` | custom filesystem adapter |

Configuration-hardening is only half the story; stored injection, text disclosure, and sensitive-path writes still need MCPGuard-style content filtering regardless of framework.

---

## Troubleshooting

**MCPGuard says "memory layout cannot be allocated" from Ollama.**
Ollama is trying to allocate more KV cache than your GPU has. Either (a) use a smaller model, (b) pin the model with `keep_alive=-1` before the run, or (c) set `OLLAMA_MAX_LOADED_MODELS=1` and restart Ollama.

**The agent hangs on Phase 1.**
Some Phase 1 prompts can generate 30+ tool calls (SI03 filename_payload loops). Give it up to 300 s per turn. If it still hangs, the model may be stuck in a retry loop — check your Ollama logs.

**PE03 destroyed my gateway config.**
Expected on Phase 1. Restore from the auto-backup. Phase 3's MCPGuard path-guard prevents this.

**My numbers differ from the published results.**
LLM sampling varies. The ±2 prompt delta is typical. What should be stable across runs:
- SI01–SI05 all COMPLIED under Phase 1 (stored injection is deterministic).
- Every exec-dependent attack REFUSED under Phase 2.
- Stored injection BLOCKED under Phase 3 (Layer 1 is deterministic).

---

## Cleanup

After running Phase 3, revert the baseUrl:
```bash
openclaw config set models.providers.ollama.baseUrl http://127.0.0.1:11434
```

Stop MCPGuard:
```bash
pkill -f mcpguard.py
# or on Windows:
# powershell -Command "Get-CimInstance Win32_Process -Filter \"name='python.exe'\" | Where-Object { $_.CommandLine -like '*mcpguard.py*' } | Stop-Process -Force"
```

If you want to fully revert to default config:
```bash
openclaw exec-policy preset yolo
# and remove tools.deny / tools.elevated from openclaw.json
openclaw gateway restart
```
