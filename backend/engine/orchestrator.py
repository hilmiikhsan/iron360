"""VAPT orchestrator — step-by-step, streamed, Claude-Code-style.

Live flow (the reliable, defensible design):
  1. PLAN     — a clear, ordered list of recon/scan steps is announced up front.
  2. EXECUTE  — the executor runs each allowlisted tool (scope-enforced), one at a
                time, streaming the command + output live (real-time agent feel).
  3. ANALYZE  — Claude analyzes the REAL tool output and extracts validated findings
                with severity, confidence and concrete config fixes. Analyzing tool
                output is a defensible task the model performs reliably; the AI never
                has to "autonomously attack", so it is not a dual-use refusal risk.

SIM flow (no API key): a scripted, realistic run so the dashboard is demoable offline.

Events pushed to emit(event); the frontend renders plan/step/exec/reasoning/finding live.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Callable

from ..config import get_settings
from ..models import Target
from . import executor, knowledge, tools

settings = get_settings()
Emit = Callable[[dict], None]


def _stopped(ev: threading.Event | None) -> bool:
    return ev is not None and ev.is_set()

ANALYST_SYSTEM = """You are Iron360, a senior VAPT analyst at RSA. You are given the raw output of
security scanners that were run against an AUTHORIZED, in-scope target during a signed engagement.
Your job is to ANALYZE that output and produce a clean, honest findings list.

Rules:
- Only report what the tool output actually supports. Do NOT invent vulnerabilities.
- status: 'confirmed' ONLY if the output contains direct evidence/PoC; otherwise 'likely' or 'needs_review'.
- Give an honest confidence (0-100). Prefer multi-tool corroboration.
- remediation must be CONCRETE: `fix_config` is the actual copy-pasteable config/code for the DETECTED
  stack (real nginx/apache directive, real parameterized query, exact header/cipher line), and `fix_steps`
  says how to apply + verify. Never vague advice.
- Reply with ONLY a JSON array (no prose, no markdown fences). Each item:
  {"title","severity":"critical|high|medium|low|info","status":"confirmed|likely|needs_review",
   "confidence":int,"affected","cve","description","evidence","remediation","fix_config","fix_steps",
   "sources":[tool names]}."""


# ------------------------------------------------------------------ pipeline
def _phases(target: Target, mode: str) -> list[tuple[str, list[tuple[str, str, dict, str]]]]:
    """Phased pipeline. Tools chosen per the ebook methodology; many sources per phase,
    results merged + deduped. (tool, host, options, description)."""
    host = target.value
    is_domain = target.kind == "domain"
    recon = []
    if is_domain:
        recon.append(("subfinder", host, {}, "Enumerate subdomains (passive)"))
        recon.append(("gau", host, {}, "Gather known URLs — Wayback/OTX (passive)"))
    recon.append(("dnsx", host, {}, "Resolve DNS records"))
    phases: list[tuple[str, list]] = [
        ("Recon", recon),
        ("Fingerprint", [
            ("httpx", host, {}, "Probe live HTTP + tech stack"),
            ("whatweb", host, {}, "Fingerprint web technologies"),
        ]),
        ("Port scan", [("nmap", host, {"sv": True}, "Top ports + service versions")]),
        ("Crawl", [("katana", host, {}, "Crawl endpoints (active)")]),
        ("Vulnerability scan", [
            ("nuclei", host, {"severity": "critical,high,medium,low"}, "Template-based vuln scan"),
            ("nikto", host, {}, "Web server vuln scan"),
            ("sslscan", host, {}, "TLS/SSL protocol + cipher audit"),
        ]),
    ]
    return phases


def _run_live(target: Target, mode: str, autonomy: str, emit: Emit,
              on_finding: Callable[[dict], None], stop_event: threading.Event | None = None) -> str:
    host = target.value
    phases = _phases(target, mode)
    flat = [(t, h, o, d) for _, steps in phases for (t, h, o, d) in steps]

    emit({"type": "plan", "steps": [{"n": i + 1, "tool": t, "desc": d} for i, (t, _, _, d) in enumerate(flat)]})
    emit({"type": "reasoning", "text": f"Authorized {mode.upper()} on {host}. {len(phases)} phases, "
          f"{len(flat)} tools, scope-enforced. Multi-source results are merged and deduped; then Claude analyzes."})

    collected: list[tuple[str, str, str]] = []
    url_lines: list[str] = []
    sub_lines: list[str] = []
    n = 0
    for phase_name, steps in phases:
        if _stopped(stop_event):
            emit({"type": "finish", "text": "Assessment stopped by operator."})
            return "Stopped by operator."
        emit({"type": "reasoning", "text": f"── Phase: {phase_name}"})
        for tool_name, h, opts, desc in steps:
            n += 1
            if _stopped(stop_event):
                emit({"type": "finish", "text": "Assessment stopped by operator."})
                return "Stopped by operator."
            tool = tools.REGISTRY.get(tool_name)
            if not tool or not tool.installed:
                emit({"type": "step", "n": n, "tool": tool_name, "status": "skipped", "text": f"{tool_name} not installed"})
                continue
            emit({"type": "step", "n": n, "tool": tool_name, "status": "running", "text": desc})
            res = executor.run(target, tool_name, h, opts, stop_event)
            emit({"type": "exec", "tool": tool_name, "host": h, "command": res.command,
                  "ok": res.ok, "exit_code": res.exit_code, "denied_reason": res.denied_reason,
                  "output": (res.stdout or res.stderr or res.denied_reason or "")[:6000],
                  "duration_s": round(res.duration_s, 1)})
            if res.ok:
                emit({"type": "step", "n": n, "tool": tool_name, "status": "done", "text": f"{desc} — {res.duration_s:.1f}s"})
                collected.append((tool_name, res.command, res.stdout or "(no output)"))
                lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                if tool_name in ("gau", "katana"):
                    url_lines += lines
                elif tool_name == "subfinder":
                    sub_lines += lines
            else:
                emit({"type": "step", "n": n, "tool": tool_name, "status": "failed", "text": res.denied_reason or "failed"})

    # Merge + dedupe (the "combine results, remove duplicates" step)
    uniq_urls = sorted({u for u in url_lines if u.startswith("http")})
    uniq_subs = sorted(set(sub_lines))
    if url_lines:
        emit({"type": "reasoning", "text": f"Merged URLs (gau+katana): {len(url_lines)} raw → {len(uniq_urls)} unique after dedupe."})
        collected.append(("merged-urls", "merge + dedupe", "\n".join(uniq_urls[:400])))
    if sub_lines:
        emit({"type": "reasoning", "text": f"Subdomains discovered: {len(uniq_subs)} unique."})

    # Intrusive validation (pentest mode) on a discovered parameterized URL
    if mode == "pentest" and not _stopped(stop_event):
        param_url = next((u for u in uniq_urls if "?" in u and "=" in u and host in u), "")
        if param_url:
            for tname in ("sqlmap", "dalfox"):
                tool = tools.REGISTRY.get(tname)
                if not tool or not tool.installed:
                    continue
                if autonomy != "auto":
                    emit({"type": "approval_required", "tool": tname,
                          "text": f"Intrusive {tname} on {param_url} held for operator approval."})
                    continue
                n += 1
                emit({"type": "reasoning", "text": f"Validating with {tname} on discovered parameter: {param_url}"})
                res = executor.run(target, tname, host, {"param_url": param_url}, stop_event)
                emit({"type": "exec", "tool": tname, "host": param_url, "command": res.command,
                      "ok": res.ok, "exit_code": res.exit_code, "denied_reason": res.denied_reason,
                      "output": (res.stdout or res.stderr or res.denied_reason or "")[:6000],
                      "duration_s": round(res.duration_s, 1)})
                if res.ok:
                    collected.append((tname, res.command, res.stdout or ""))

    if _stopped(stop_event):
        emit({"type": "finish", "text": "Assessment stopped by operator."})
        return "Stopped by operator."
    if not collected:
        emit({"type": "note", "text": "No executor tools available / nothing collected."})
        emit({"type": "finish", "text": "No output to analyze."})
        return "No output collected."

    emit({"type": "reasoning", "text": "Analyzing all collected output with Claude + extracting validated findings…"})
    findings = _ai_extract_findings(target, collected, emit)
    for f in findings:
        on_finding(f)
        emit({"type": "finding", "finding": f})

    summary = (f"Live {mode.upper()} complete on {host}: {len(collected)} data source(s), "
               f"{len(uniq_urls)} unique URLs, {len(findings)} finding(s) analyzed by Claude.")
    emit({"type": "finish", "text": summary})
    return summary


def _ai_extract_findings(target: Target, collected: list[tuple[str, str, str]], emit: Emit) -> list[dict]:
    """Single Claude call: analyze real tool output → structured findings."""
    from . import llm

    blob = []
    for tool_name, command, output in collected:
        blob.append(f"### {tool_name}\n$ {command}\n{output[:6000]}")
    kb = knowledge.methodology_brief(f"web vulnerability {target.value} owasp sqli xss headers tls")
    user = (f"Target: {target.label} ({target.value}), engagement: {target.engagement or 'internal'}.\n"
            f"Authorized scope: {', '.join([target.value] + (target.scope_extra or []))}.\n\n"
            f"Scanner output to analyze:\n\n" + "\n\n".join(blob) + f"\n\n{kb}\n\n"
            "Extract the findings as the JSON array specified. If the output shows no issues, return [].")
    try:
        client = llm.make_client()
        resp = client.messages.create(
            model=settings.ai_model, max_tokens=8000,
            system=ANALYST_SYSTEM,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": user}],
        )
        if resp.stop_reason == "refusal":
            emit({"type": "note", "text": "AI analysis was declined by the safety classifier."})
            return []
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        start, end = text.find("["), text.rfind("]")
        if start == -1 or end == -1:
            emit({"type": "note", "text": "AI returned no structured findings."})
            return []
        data = json.loads(text[start:end + 1])
        out = []
        for f in data if isinstance(data, list) else []:
            if not isinstance(f, dict) or not f.get("title"):
                continue
            out.append({
                "title": str(f.get("title"))[:255], "severity": f.get("severity", "info"),
                "status": f.get("status", "needs_review"), "confidence": int(f.get("confidence", 0) or 0),
                "affected": str(f.get("affected", ""))[:255], "cve": str(f.get("cve", ""))[:64],
                "description": str(f.get("description", "")), "evidence": str(f.get("evidence", "")),
                "remediation": str(f.get("remediation", "")), "fix_config": str(f.get("fix_config", "")),
                "fix_steps": str(f.get("fix_steps", "")),
                "sources": f.get("sources", []) if isinstance(f.get("sources"), list) else [],
            })
        return out
    except Exception as e:  # noqa: BLE001
        emit({"type": "note", "text": f"AI analysis error: {e}"})
        return []


# ------------------------------------------------------------------ simulation
def _run_sim(target: Target, mode: str, autonomy: str, emit: Emit,
             on_finding: Callable[[dict], None], stop_event: threading.Event | None = None) -> str:
    host = target.value
    plan = [
        ("subfinder", "Enumerate subdomains (passive)"),
        ("httpx", "Probe live HTTP service + fingerprint stack"),
        ("nuclei", "Template-based vulnerability scan"),
        ("sqlmap", "Validate suspected SQL injection"),
        ("ai-analysis", "Analyze output + extract validated findings"),
    ]
    emit({"type": "plan", "steps": [{"n": i + 1, "tool": t, "desc": d} for i, (t, d) in enumerate(plan)]})

    def step(delay, ev):
        if _stopped(stop_event):
            return
        time.sleep(delay)
        if _stopped(stop_event):
            return
        emit(ev)

    step(0.2, {"type": "reasoning", "text": f"Planning {mode.upper()} for in-scope target {host}. Starting passive recon."})
    step(0.3, {"type": "step", "n": 1, "tool": "subfinder", "status": "running", "text": "Enumerate subdomains"})
    step(0.5, {"type": "exec", "tool": "subfinder", "host": host, "command": f"subfinder -silent -d {host}",
               "ok": True, "exit_code": 0, "output": f"www.{host}\napi.{host}\ndev.{host}", "duration_s": 2.1})
    step(0.2, {"type": "step", "n": 1, "tool": "subfinder", "status": "done", "text": "3 subdomains found"})
    step(0.3, {"type": "step", "n": 2, "tool": "httpx", "status": "running", "text": "Probe HTTP + tech"})
    step(0.5, {"type": "exec", "tool": "httpx", "host": f"www.{host}", "command": f"httpx -silent -title -tech-detect -u www.{host}",
               "ok": True, "exit_code": 0, "output": f"https://www.{host} [200] [Login] [nginx, PHP, jQuery]", "duration_s": 1.4})
    step(0.2, {"type": "step", "n": 2, "tool": "httpx", "status": "done", "text": "Stack: nginx + PHP"})
    step(0.3, {"type": "step", "n": 3, "tool": "nuclei", "status": "running", "text": "Vulnerability scan"})
    step(0.6, {"type": "exec", "tool": "nuclei", "host": f"www.{host}", "command": f"nuclei -severity critical,high,medium -u https://www.{host}",
               "ok": True, "exit_code": 0, "output": "[medium] tls-version :: TLS 1.0 enabled\n[info] missing-csp-header", "duration_s": 9.3})
    step(0.2, {"type": "step", "n": 3, "tool": "nuclei", "status": "done", "text": "2 signals; validating"})
    step(0.3, {"type": "reasoning", "text": "Possible SQLi on api. Per anti-FP policy I validate with a reproducing probe before reporting."})
    step(0.3, {"type": "step", "n": 4, "tool": "sqlmap", "status": "running", "text": "Validate SQLi"})
    step(0.6, {"type": "exec", "tool": "sqlmap", "host": f"api.{host}", "command": f"sqlmap --batch -u https://api.{host}/v1/items?id=1",
               "ok": True, "exit_code": 0, "output": "Parameter 'id' is vulnerable (boolean-based blind). Payload: id=1 AND 1=1", "duration_s": 14.8})
    step(0.2, {"type": "step", "n": 4, "tool": "sqlmap", "status": "done", "text": "SQLi reproduced (1=1 vs 1=2). False positive: NO."})
    step(0.3, {"type": "step", "n": 5, "tool": "ai-analysis", "status": "running", "text": "Extracting findings"})
    f1 = {
        "title": "SQL Injection on /v1/items (id parameter)", "severity": "high", "status": "confirmed",
        "confidence": 94, "affected": f"https://api.{host}/v1/items?id=", "cve": "",
        "description": "Boolean-based blind SQL injection in the 'id' parameter (detected stack: PHP + MySQL).",
        "evidence": "sqlmap confirmed: id=1 AND 1=1 -> 200/data; id=1 AND 1=2 -> 200/empty. Differential proves injection.",
        "remediation": "Replace string-concatenated SQL with a parameterized (prepared) statement and type-cast 'id'.",
        "fix_config": ("// Fix — PDO prepared statement (PHP/MySQL):\n"
                       "$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);\n"
                       "if ($id === false) { http_response_code(400); exit('invalid id'); }\n"
                       "$stmt = $pdo->prepare('SELECT * FROM items WHERE id = :id');\n"
                       "$stmt->execute([':id' => $id]);"),
        "fix_steps": ("1. Patch every query interpolating request input.\n"
                      "2. Add a WAF virtual-patch (Ironcloud) on 'id' as interim mitigation.\n"
                      f"3. Re-test: sqlmap --batch -u https://api.{host}/v1/items?id=1 must report NOT injectable."),
        "sources": ["nuclei", "sqlmap"],
    }
    step(0.3, {"type": "finding", "finding": f1}); on_finding(f1)
    f2 = {
        "title": "TLS 1.0/1.1 enabled", "severity": "medium", "status": "likely", "confidence": 70,
        "affected": f"https://www.{host}", "description": "Legacy TLS 1.0/1.1 negotiated on nginx (PCI-DSS fail).",
        "evidence": "nuclei tls-version template matched TLS 1.0.",
        "remediation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
        "fix_config": ("# /etc/nginx/conf.d/ssl.conf (nginx)\n"
                       "ssl_protocols TLSv1.2 TLSv1.3;\n"
                       "ssl_prefer_server_ciphers on;\n"
                       "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"),
        "fix_steps": f"1. Apply, then: nginx -t && nginx -s reload.\n2. Verify: nmap --script ssl-enum-ciphers -p 443 www.{host}.",
        "sources": ["nuclei"],
    }
    step(0.3, {"type": "finding", "finding": f2}); on_finding(f2)
    step(0.2, {"type": "step", "n": 5, "tool": "ai-analysis", "status": "done", "text": "2 findings extracted"})
    summary = ("Assessment complete (SIMULATION). 1 confirmed High (SQLi, validated), 1 likely Medium (TLS). "
               "All steps stayed in-scope. Connect live AI + install scanners for real execution.")
    step(0.2, {"type": "finish", "text": summary})
    return summary


# ------------------------------------------------------------------ entry point
def run_assessment(target: Target, mode: str, autonomy: str, emit: Emit,
                   on_finding: Callable[[dict], None], stop_event: threading.Event | None = None) -> str:
    emit({"type": "note", "text": f"Engine: {'LIVE (Claude)' if settings.ai_live else 'SIMULATION'}"})
    try:
        if settings.ai_live:
            return _run_live(target, mode, autonomy, emit, on_finding, stop_event)
        return _run_sim(target, mode, autonomy, emit, on_finding, stop_event)
    except Exception as e:  # noqa: BLE001
        emit({"type": "error", "text": f"engine error: {e}"})
        return f"Assessment failed: {e}"
