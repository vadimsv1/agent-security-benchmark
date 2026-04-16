#!/usr/bin/env python3
"""Quick demo - replay 3 real attacks with and without MCPGuard.

No OpenClaw or Ollama required. Reads prerecorded results from
../results/results_default.jsonl and ../results/results_mcpguard.jsonl
and prints a side-by-side walkthrough in the terminal.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


if sys.platform == "win32":
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREY = "\033[90m"

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "benchmark" / "test_prompts.jsonl"
DEFAULT_RESULTS = ROOT / "results" / "results_default.jsonl"
MCP_RESULTS = ROOT / "results" / "results_mcpguard.jsonl"

DEMO_IDS = ["EX02", "SI01", "SI03"]


def load_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def find(records: list[dict], id_: str) -> dict | None:
    for r in records:
        if r.get("id") == id_:
            return r
    return None


def fmt_verdict(c: dict) -> str:
    v = c.get("verdict", "?")
    blocked = bool(c.get("mcpguard_blocked_any", False))
    if v == "COMPLIED":
        color = RED
    elif v in ("BLOCKED", "REFUSED", "PARTIAL"):
        color = GREEN
    else:
        color = YELLOW
    tag = f" {DIM}(MCPGuard intercepted){RESET}" if blocked else ""
    return f"{color}{BOLD}{v}{RESET}{tag}"


def print_attack(idx: int, total: int, pid: str, prompt_rec: dict,
                 default_rec: dict, mcp_rec: dict) -> None:
    technique = prompt_rec.get("technique", "?")
    turn = prompt_rec["turns"][0]
    if len(turn) > 200:
        turn = turn[:197] + "..."

    print()
    print(f"{CYAN}{BOLD}[{idx}/{total}] {pid}  -  {technique}{RESET}")
    print(f"{GREY}{'-' * 68}{RESET}")
    print(f"  {BOLD}Attack prompt:{RESET}")
    print(f"    {YELLOW}{turn}{RESET}")
    print()

    d = default_rec["classification"]
    print(f"  {BOLD}Without MCPGuard{RESET} {DIM}(Phase 1, stock agent){RESET}")
    print(f"    Verdict:            {fmt_verdict(d)}")
    print(f"    Tool calls: {d.get('tool_call_count', 0):>3}   "
          f"Exfil calls: {d.get('exfil_call_count', 0):>2}   "
          f"Sensitive touches: {d.get('sensitive_touch_count', 0):>2}")
    mi = d.get("matched_indicators") or []
    if mi:
        print(f"    {RED}Attack succeeded - indicators matched:{RESET}")
        for ind in mi[:3]:
            print(f"      {RED}x{RESET} {ind}")
    print()

    m = mcp_rec["classification"]
    print(f"  {BOLD}With MCPGuard{RESET} {DIM}(Phase 3, 5-layer proxy){RESET}")
    print(f"    Verdict:            {fmt_verdict(m)}")
    print(f"    Tool calls: {m.get('tool_call_count', 0):>3}   "
          f"Exfil calls: {m.get('exfil_call_count', 0):>2}   "
          f"Sensitive touches: {m.get('sensitive_touch_count', 0):>2}")
    if m.get("mcpguard_blocked_any"):
        print(f"    {GREEN}MCPGuard blocked the attack chain.{RESET}")
    elif (m.get("matched_indicators") or []):
        print(f"    {RED}Attack still succeeded - indicators matched.{RESET}")
    else:
        print(f"    {GREEN}Agent refused the request.{RESET}")


def main() -> int:
    for p in (PROMPTS, DEFAULT_RESULTS, MCP_RESULTS):
        if not p.exists():
            print(f"{RED}Missing data file: {p}{RESET}", file=sys.stderr)
            return 1

    prompts = load_jsonl(PROMPTS)
    defaults = load_jsonl(DEFAULT_RESULTS)
    mcp = load_jsonl(MCP_RESULTS)

    print()
    print(f"{CYAN}{BOLD}{'=' * 68}{RESET}")
    print(f"  {BOLD}MCPGuard demo  -  3 real attack runs, side by side{RESET}")
    print(f"  {DIM}replayed from results/ (no OpenClaw or Ollama required){RESET}")
    print(f"{CYAN}{BOLD}{'=' * 68}{RESET}")

    d_ok = m_ok = 0
    for i, pid in enumerate(DEMO_IDS, 1):
        pr = find(prompts, pid)
        dr = find(defaults, pid)
        mr = find(mcp, pid)
        if not (pr and dr and mr):
            print(f"{RED}missing data for {pid}{RESET}")
            continue
        print_attack(i, len(DEMO_IDS), pid, pr, dr, mr)
        if dr["classification"].get("verdict") == "COMPLIED":
            d_ok += 1
        if mr["classification"].get("verdict") == "COMPLIED":
            m_ok += 1

    print()
    print(f"{CYAN}{BOLD}{'=' * 68}{RESET}")
    print(f"  {BOLD}Summary{RESET}")
    n = len(DEMO_IDS)
    print(f"    Without MCPGuard:  {RED}{BOLD}{d_ok}/{n} succeeded{RESET}")
    print(f"    With MCPGuard:     {GREEN}{BOLD}{m_ok}/{n} succeeded{RESET}")
    print()
    print(f"  {DIM}Full 30-prompt numbers in results/report_*.md and docs/FULL_REPORT.md{RESET}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
