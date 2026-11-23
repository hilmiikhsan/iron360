"""Interactive pentest agent — Claude-Code-style tool-use loop.

The operator types prompts, the AI decides which tools to run, executes them
via the scope-enforced executor, and streams results real-time. Multi-turn
conversation: the operator can steer the pentest at every step.
"""
from __future__ import annotations

import json
import threading
from typing import Callable

from ..config import get_settings
from ..models import Target
from . import executor, tools, knowledge

settings = get_settings()
Emit = Callable[[dict], None]

AGENT_SYSTEM = """\
You are Iron360, an expert penetration testing AI agent at RSA. You operate like
an interactive terminal agent (Claude Code style): the operator gives you
instructions and you execute them step by step, streaming your reasoning and
tool output in real-time.

## Rules
1. ONLY run tools against the authorized, in-scope target provided.
2. NEVER fabricate tool output or findings — only report what tools actually returned.
3. Stream your reasoning so the operator follows your thought process.
4. When you find something, explain it and decide what to do next.
5. For intrusive tools (sqlmap, ffuf, etc.), explain briefly before running.
6. Follow the operator's instructions precisely. If they say "enumerate subdomains",
   do that. If they say "check for SQLi on endpoint X", do that.
7. After running tools, analyze the output and extract findings.
8. When you identify a vulnerability, use the report_finding tool with concrete evidence.
9. Merge + deduplicate results when running multiple tools of the same category.
10. You can run multiple tools in sequence without asking — be autonomous like Claude Code.

## Methodology
- Subdomain enumeration: combine subfinder + assetfinder + amass + findomain, merge + dedup.
- URL gathering: gau + waybackurls, merge + dedup, then parameter extraction + gf-pattern tagging.
- Vulnerability scanning: nuclei, nmap NSE, nikto, sslscan.
- Active testing: sqlmap (SQLi), dalfox/xsstrike (XSS), commix (command injection).
- Content discovery: ffuf, gobuster, feroxbuster, dirsearch.
- CVE-specific scanning: tools named cphunter_* are auto-discovered from CPHunter's
  MODULE_CATALOG. Each runs a targeted CVE check (fingerprint + PoC). Use them when
  you detect a matching service (Java app → java4shell, nginx → nginx2root, SSH → sshole, etc.).
- Always validate findings — a single scanner hit is 'needs_review', not 'confirmed'.

## Target context
{target_context}
"""


def _build_tool_defs() -> list[dict]:
    """Build Claude tool definitions from the REGISTRY."""
    defs = []
    for name, tool in tools.REGISTRY.items():
        if not tool.installed:
            continue
        props = {"host": {"type": "string", "description": "Target host/domain to scan"}}
        required = ["host"]

        if name == "nmap":
            props["ports"] = {"type": "string", "description": "Ports, e.g. '80,443' or 'top1000'"}
            props["sv"] = {"type": "boolean", "description": "Service version detection (-sV)"}
            props["scripts"] = {"type": "string", "description": "NSE scripts, e.g. 'vuln'"}
        elif name in ("sqlmap", "dalfox", "commix", "xsstrike"):
            props["param_url"] = {
                "type": "string",
                "description": "Full URL with query param, e.g. https://host/page?id=1",
            }
            required.append("param_url")
        elif name in ("ffuf", "gobuster", "feroxbuster"):
            props["wordlist"] = {"type": "string", "description": "Wordlist absolute path"}
        elif name == "nuclei":
            props["severity"] = {"type": "string", "description": "Filter, e.g. 'critical,high,medium'"}
            props["tags"] = {"type": "string", "description": "Template tags, e.g. 'cve,exposure'"}
        elif name == "droopescan":
            props["cms"] = {"type": "string", "description": "CMS: drupal, wordpress, joomla"}
        elif name in ("whatweb", "wafw00f", "nikto", "katana", "hakrawler",
                       "wpscan", "dirsearch", "nuclei", "feroxbuster"):
            props["scheme"] = {
                "type": "string", "description": "http or https", "enum": ["http", "https"],
            }
        elif name.startswith("cphunter_"):
            props["port"] = {"type": "string", "description": "Target port (e.g. '80', '443', '22')"}

        defs.append({
            "name": f"run_{name}",
            "description": f"[{tool.category}/{tool.intensity}] {tool.description}",
            "input_schema": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        })

    defs.append({
        "name": "report_finding",
        "description": "Report a vulnerability finding with evidence and remediation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["confirmed", "likely", "needs_review"]},
                "confidence": {"type": "integer", "description": "0-100"},
                "affected": {"type": "string", "description": "Affected URL/host/service"},
                "cve": {"type": "string", "description": "CVE ID if applicable"},
                "description": {"type": "string"},
                "evidence": {"type": "string", "description": "Actual evidence from tool output"},
                "remediation": {"type": "string"},
                "fix_config": {"type": "string", "description": "Copy-pasteable config fix"},
                "fix_steps": {"type": "string", "description": "Step-by-step fix + verify"},
            },
            "required": ["title", "severity", "status", "confidence", "affected",
                         "description", "evidence", "remediation"],
        },
    })

    return defs


def run_agent_turn(
    target: Target,
    messages: list[dict],
    emit: Emit,
    on_finding: Callable[[dict], None],
    stop_event: threading.Event | None = None,
) -> list[dict]:
    """Run one full agent turn: call Claude, execute tool calls, loop until done.

    Returns the updated messages list (for multi-turn persistence).
    """
    from . import llm

    client = llm.make_client()
    tool_defs = _build_tool_defs()

    target_ctx = (
        f"Target: {target.label} ({target.value}), kind: {target.kind}\n"
        f"Engagement: {target.engagement or 'internal test'}\n"
        f"Scope: {target.value}"
        + (f", {', '.join(target.scope_extra)}" if target.scope_extra else "")
    )
    system = AGENT_SYSTEM.format(target_context=target_ctx)

    max_iterations = 25
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        if stop_event and stop_event.is_set():
            emit({"type": "agent_text", "text": "Stopped by operator."})
            break

        emit({"type": "agent_thinking"})

        try:
            resp = client.messages.create(
                model=settings.ai_model,
                max_tokens=4096,
                system=system,
                tools=tool_defs,
                thinking={"type": "adaptive"},
                messages=messages,
            )
        except Exception as e:
            emit({"type": "agent_text", "text": f"AI error: {e}"})
            break

        if resp.stop_reason == "refusal":
            emit({"type": "agent_text", "text": "The AI declined this request."})
            break

        assistant_content = []
        tool_calls = []

        for block in resp.content:
            if getattr(block, "type", "") == "thinking":
                emit({"type": "agent_thinking_text", "text": block.thinking})
            elif getattr(block, "type", "") == "text":
                emit({"type": "agent_text", "text": block.text})
                assistant_content.append({"type": "text", "text": block.text})
            elif getattr(block, "type", "") == "tool_use":
                tool_calls.append(block)
                assistant_content.append({
                    "type": "tool_use", "id": block.id,
                    "name": block.name, "input": block.input,
                })

        messages.append({"role": "assistant", "content": assistant_content})

        if not tool_calls:
            break

        tool_results = []
        for tc in tool_calls:
            if stop_event and stop_event.is_set():
                tool_results.append({
                    "type": "tool_result", "tool_use_id": tc.id,
                    "content": "Stopped by operator.", "is_error": True,
                })
                continue

            result = _execute_tool(target, tc.name, tc.input, emit, stop_event, on_finding)
            tool_results.append({
                "type": "tool_result", "tool_use_id": tc.id,
                "content": result["output"],
                "is_error": result.get("error", False),
            })

        messages.append({"role": "user", "content": tool_results})

        if resp.stop_reason == "end_turn":
            break

    return messages


def _execute_tool(
    target: Target, tool_name: str, inputs: dict, emit: Emit,
    stop_event: threading.Event | None,
    on_finding: Callable[[dict], None],
) -> dict:
    """Execute a single tool call from the agent."""
    if tool_name == "report_finding":
        finding = dict(inputs)
        finding.setdefault("sources", [])
        finding.setdefault("fix_config", "")
        finding.setdefault("fix_steps", "")
        finding.setdefault("cve", "")
        on_finding(finding)
        emit({"type": "finding", "finding": finding})
        return {"output": f"Finding reported: {finding.get('title', '')}", "error": False}

    actual = tool_name.removeprefix("run_")
    tool = tools.REGISTRY.get(actual)
    if not tool:
        return {"output": f"Unknown tool: {actual}", "error": True}
    if not tool.installed:
        return {"output": f"Tool {actual} not installed.", "error": True}

    host = inputs.get("host", target.value)
    opts = {k: v for k, v in inputs.items() if k != "host"}

    emit({"type": "agent_tool_start", "tool": actual, "host": host,
          "text": f"Running {actual} on {host}…"})

    line_buf: list[str] = []

    def _line_emit(line: str) -> None:
        s = line.strip()
        if s:
            line_buf.append(s)
            emit({"type": "log", "tool": actual, "line": s})

    res = executor.run(target, actual, host, opts, stop_event, line_emit=_line_emit)

    emit({"type": "exec", "tool": actual, "host": host, "command": res.command,
          "ok": res.ok, "exit_code": res.exit_code,
          "denied_reason": res.denied_reason,
          "output": f"({len(line_buf)} lines)" if res.ok else (res.denied_reason or ""),
          "duration_s": round(res.duration_s, 1)})

    if not res.ok:
        return {"output": f"Tool failed: {res.denied_reason}", "error": True}

    output = res.stdout or "(no output)"
    if len(output) > 15000:
        output = output[:15000] + f"\n… (truncated, {len(res.stdout)} total chars)"

    return {"output": output, "error": False}
