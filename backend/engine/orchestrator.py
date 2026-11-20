"""Agentic VAPT orchestrator.

The AI is a co-pilot that PLANS and DECIDES; it never runs a shell. Each step it
may call an allowlisted tool (run through the executor, which enforces scope) or
record a validated finding. The loop: plan -> act -> observe -> decide, until the
agent calls `finish` or a step budget is hit.

Two modes:
  - LIVE  (ANTHROPIC_API_KEY set): real Claude drives real tools via the executor.
  - SIM   (no key): a deterministic, realistic script — no tokens, no live tools —
          so the dashboard is fully demoable offline.

Events are pushed to `emit(event)` so the API layer can stream them over WebSocket
and persist the timeline.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from ..config import get_settings
from ..models import Target
from . import executor, knowledge, tools

settings = get_settings()

Emit = Callable[[dict], None]
MAX_STEPS = 24

SYSTEM_PROMPT = """You are Iron360, an expert VAPT co-pilot for RSA, operating ONLY against
targets that are authorized and in-scope for a signed engagement (NDA/SOW). You assist a
human penetration tester; a human always has the final say on every finding.

Hard rules:
- You never have raw shell access. You act ONLY by calling the provided tools.
- The executor enforces scope. If a target is refused, DO NOT retry it — note it and move on.
- Work in-scope only. Never attempt to reach a host outside the engagement scope.

Methodology (OWASP WSTG + NIST SP 800-115), anti-false-positive discipline:
1. Recon first (subdomains, DNS, live HTTP, tech stack), then service/port VA, then targeted checks.
2. Adapt known techniques (OWASP Top 10, documented bypasses, payload references) to what you observe.
3. BEFORE recording any finding as 'confirmed', you must have reproducible evidence (a PoC the tool
   output actually demonstrates). If you only have a scanner hit with no proof, record it as 'likely'
   or 'needs_review' with an honest confidence score — never inflate.
4. Prefer multi-tool corroboration. A single low-signal hit is 'needs_review', not 'confirmed'.
5. Challenge your own results: ask "could this be a false positive?" and say why not before confirming.

Remediation must be CONCRETE, not generic. For every finding, `fix_config` must contain the actual
config/code the client can copy-paste — tailored to the stack you detected during recon (e.g. the real
nginx/apache directive, the real parameterized-query snippet in the detected language, the exact security
header, the precise cipher/protocol line). Never write vague advice like "use prepared statements"; write
the statement. `fix_steps` lists how to apply it and how to verify the fix worked.

When you have completed the assessment, call `finish` with a short summary.
Think step by step, but keep each spoken message concise and operator-focused."""


# ------------------------------------------------------------------ tool schemas
def _tool_schemas(mode: str) -> list[dict]:
    """Expose allowlisted tools to the model, gated by mode + install status."""
    allow_intensity = {"passive", "active"} if mode == "va" else {"passive", "active", "intrusive"}
    schemas: list[dict] = []
    for name, tool in tools.REGISTRY.items():
        if tool.intensity not in allow_intensity or not tool.installed:
            continue
        schemas.append({
            "name": f"tool_{name}",
            "description": f"[{tool.category}/{tool.intensity}] {tool.description}",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "In-scope host/domain/IP to target."},
                    "options": {"type": "object", "description": "Tool-specific options (see description)."},
                    "rationale": {"type": "string", "description": "Why this step, in one sentence."},
                },
                "required": ["host"],
            },
        })
    schemas.append({
        "name": "record_finding",
        "description": "Record a vulnerability finding with an honest validation state and confidence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["confirmed", "likely", "needs_review", "false_positive"]},
                "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                "affected": {"type": "string", "description": "URL/host/parameter affected."},
                "cve": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "string", "description": "The PoC / proof from tool output."},
                "remediation": {"type": "string", "description": "One-line summary of the fix."},
                "fix_config": {"type": "string", "description": "Concrete, copy-pasteable config/code for the "
                               "DETECTED stack (actual directive/snippet, not generic advice)."},
                "fix_steps": {"type": "string", "description": "How to apply the fix and how to verify it worked."},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Tools that corroborated it."},
            },
            "required": ["title", "severity", "status", "confidence"],
        },
    })
    schemas.append({
        "name": "finish",
        "description": "End the assessment with a concise summary.",
        "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
    })
    return schemas


# ------------------------------------------------------------------ live runner
def _run_live(target: Target, mode: str, autonomy: str, emit: Emit,
              on_finding: Callable[[dict], None]) -> str:
    from . import llm

    client = llm.make_client()
    kb = knowledge.methodology_brief(f"{mode} web pentest {target.value} owasp recon sqli xss")
    user_intro = (
        f"Engagement: {target.engagement or 'internal'}\n"
        f"Target workspace: {target.label} ({target.value}), kind={target.kind}\n"
        f"Authorized scope: {', '.join([target.value] + (target.scope_extra or []))}\n"
        f"Mode: {mode.upper()}  Autonomy: {autonomy}\n\n{kb}\n\nBegin the assessment."
    )
    messages: list[dict] = [{"role": "user", "content": user_intro}]
    schemas = _tool_schemas(mode)
    summary = ""

    for step in range(MAX_STEPS):
        resp = client.messages.create(
            model=settings.ai_model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=schemas,
            thinking={"type": "adaptive"},
            output_config={"effort": settings.ai_effort},
            messages=messages,
        )
        if resp.stop_reason == "refusal":
            emit({"type": "note", "text": "AI safety classifier declined this step; stopping."})
            break

        assistant_content: list[Any] = []
        tool_results: list[dict] = []
        for block in resp.content:
            if block.type == "text" and block.text.strip():
                emit({"type": "reasoning", "text": block.text.strip()})
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "thinking":
                assistant_content.append(block.model_dump())
            elif block.type == "tool_use":
                assistant_content.append(block.model_dump())
                result = _dispatch_tool(target, mode, autonomy, block, emit, on_finding)
                if result.get("_finish"):
                    summary = result["summary"]
                    messages.append({"role": "assistant", "content": assistant_content})
                    return summary
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result["content"],
                    "is_error": result.get("is_error", False),
                })

        messages.append({"role": "assistant", "content": assistant_content})
        if not tool_results:
            # No tool calls and no finish → model is done talking.
            summary = summary or (resp.content[0].text if resp.content else "Assessment ended.")
            break
        messages.append({"role": "user", "content": tool_results})

    return summary or "Assessment completed (step budget reached)."


def _dispatch_tool(target: Target, mode: str, autonomy: str, block, emit: Emit,
                   on_finding: Callable[[dict], None]) -> dict:
    name = block.name
    args = block.input or {}

    if name == "finish":
        emit({"type": "finish", "text": args.get("summary", "")})
        return {"_finish": True, "summary": args.get("summary", "")}

    if name == "record_finding":
        on_finding(args)
        emit({"type": "finding", "finding": args})
        return {"content": "Finding recorded."}

    # tool_<name>
    tool_name = name.removeprefix("tool_")
    tool = tools.REGISTRY.get(tool_name)
    host = args.get("host", target.value)
    options = args.get("options") or {}
    rationale = args.get("rationale", "")
    emit({"type": "reasoning", "text": f"→ {tool_name} on {host}" + (f" — {rationale}" if rationale else "")})

    # Approval gate for intrusive actions when not in auto mode.
    if tool and tool.intensity == "intrusive" and autonomy != "auto":
        emit({"type": "approval_required", "tool": tool_name, "host": host,
              "text": f"Intrusive step '{tool_name}' on {host} held for operator approval (autonomy=approve)."})
        return {"content": f"HELD: '{tool_name}' requires operator approval in approve mode. Continue with non-intrusive steps."}

    res = executor.run(target, tool_name, host, options)
    emit({
        "type": "exec",
        "tool": tool_name, "host": host, "command": res.command,
        "ok": res.ok, "exit_code": res.exit_code,
        "denied_reason": res.denied_reason,
        "output": (res.stdout or res.stderr or res.denied_reason)[:6000],
        "duration_s": round(res.duration_s, 1),
    })
    if not res.ok:
        return {"content": f"DENIED/FAILED: {res.denied_reason}", "is_error": True}
    body = res.stdout.strip() or "(no stdout)"
    return {"content": f"exit={res.exit_code} time={res.duration_s:.1f}s\n{body[:8000]}"}


# ------------------------------------------------------------------ simulation
def _run_sim(target: Target, mode: str, autonomy: str, emit: Emit,
             on_finding: Callable[[dict], None]) -> str:
    host = target.value

    def step(delay: float, event: dict) -> None:
        time.sleep(delay)
        emit(event)

    step(0.3, {"type": "reasoning", "text": f"Planning {mode.upper()} for in-scope target {host}. Starting with passive recon."})
    step(0.6, {"type": "exec", "tool": "subfinder", "host": host, "command": f"subfinder -silent -d {host}",
               "ok": True, "exit_code": 0, "output": f"www.{host}\napi.{host}\ndev.{host}", "duration_s": 2.1})
    step(0.6, {"type": "reasoning", "text": "Three subdomains resolved. Probing live HTTP services + tech stack."})
    step(0.6, {"type": "exec", "tool": "httpx", "host": f"www.{host}", "command": f"httpx -silent -title -tech-detect -u www.{host}",
               "ok": True, "exit_code": 0, "output": f"https://www.{host} [200] [Login] [nginx, PHP, jQuery]", "duration_s": 1.4})
    step(0.6, {"type": "exec", "tool": "nuclei", "host": f"www.{host}", "command": f"nuclei -severity critical,high,medium -u https://www.{host}",
               "ok": True, "exit_code": 0, "output": "[medium] tls-version :: TLS 1.0 enabled\n[info] missing-csp-header", "duration_s": 9.3})
    step(0.7, {"type": "reasoning", "text": "Scanner flagged a possible SQLi on api. Per anti-FP policy I will NOT report it yet — validating with a reproducing probe."})
    step(0.8, {"type": "exec", "tool": "sqlmap", "host": f"api.{host}", "command": f"sqlmap --batch -u https://api.{host}/v1/items?id=1",
               "ok": True, "exit_code": 0, "output": "Parameter 'id' is vulnerable (boolean-based blind). Payload: id=1 AND 1=1", "duration_s": 14.8})
    step(0.5, {"type": "reasoning", "text": "Reproduced the injection twice (1=1 vs 1=2 differ). False positive: NO. Confidence high. Recording as CONFIRMED."})
    f1 = {
        "title": "SQL Injection on /v1/items (id parameter)", "severity": "high", "status": "confirmed",
        "confidence": 94, "affected": f"https://api.{host}/v1/items?id=", "cve": "",
        "description": "Boolean-based blind SQL injection in the 'id' parameter of the items API (detected stack: PHP + MySQL).",
        "evidence": "sqlmap confirmed: id=1 AND 1=1 → 200/data; id=1 AND 1=2 → 200/empty. Differential proves injection.",
        "remediation": "Replace string-concatenated SQL with a parameterized (prepared) statement and type-cast 'id'.",
        "fix_config": (
            "// Vulnerable (detected): \n"
            "// $q = \"SELECT * FROM items WHERE id = \".$_GET['id'];\n\n"
            "// Fix — PDO prepared statement (PHP/MySQL):\n"
            "$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\n"
            "if ($id === false) { http_response_code(400); exit('invalid id'); }\n"
            "$stmt = $pdo->prepare('SELECT * FROM items WHERE id = :id');\n"
            "$stmt->execute([':id' => $id]);\n"
            "$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);"
        ),
        "fix_steps": (
            "1. Patch every query that interpolates request input (grep for \"$_GET\"/\"$_POST\" inside SQL).\n"
            "2. Add a WAF virtual-patch rule on the 'id' param as interim mitigation (Ironcloud WAF).\n"
            "3. Re-test: `sqlmap --batch -u https://api." + host + "/v1/items?id=1` must report NOT injectable."
        ),
        "sources": ["nuclei", "sqlmap"],
    }
    step(0.3, {"type": "finding", "finding": f1}); on_finding(f1)
    f2 = {
        "title": "TLS 1.0/1.1 enabled", "severity": "medium", "status": "likely", "confidence": 70,
        "affected": f"https://www.{host}", "description": "Legacy TLS 1.0/1.1 negotiated on nginx — weak protocol (PCI-DSS fail).",
        "evidence": "nuclei tls-version template matched TLS 1.0.",
        "remediation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+ with a strong cipher suite.",
        "fix_config": (
            "# /etc/nginx/conf.d/ssl.conf  (detected stack: nginx)\n"
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_prefer_server_ciphers on;\n"
            "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;\n"
            "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"
        ),
        "fix_steps": (
            "1. Apply the block, then `nginx -t && nginx -s reload`.\n"
            "2. Verify: `nmap --script ssl-enum-ciphers -p 443 www." + host + "` should show only TLSv1.2/1.3."
        ),
        "sources": ["nuclei"],
    }
    step(0.3, {"type": "finding", "finding": f2}); on_finding(f2)
    summary = ("Assessment complete (SIMULATION). 1 confirmed High (SQLi, validated), 1 likely Medium (TLS 1.0). "
               "All steps stayed in-scope. Set ANTHROPIC_API_KEY to run the live AI engine against real tools.")
    step(0.4, {"type": "finish", "text": summary})
    return summary


# ------------------------------------------------------------------ entry point
def run_assessment(target: Target, mode: str, autonomy: str, emit: Emit,
                   on_finding: Callable[[dict], None]) -> str:
    emit({"type": "note", "text": f"Engine: {'LIVE (Claude)' if settings.ai_live else 'SIMULATION (no API key)'}"})
    try:
        if settings.ai_live:
            return _run_live(target, mode, autonomy, emit, on_finding)
        return _run_sim(target, mode, autonomy, emit, on_finding)
    except Exception as e:  # noqa: BLE001
        emit({"type": "error", "text": f"engine error: {e}"})
        return f"Assessment failed: {e}"
