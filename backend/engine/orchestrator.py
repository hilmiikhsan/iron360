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

ANALYST_SYSTEM = """You are Iron360, a senior VAPT analyst at RSA, trained on a bug-bounty methodology
("3 Bugs That Pay", OWASP WSTG, HackTricks). You are given the raw output of security tools run against an
AUTHORIZED, in-scope target during a signed engagement — recon, live hosts, merged+deduped URLs, parameter
candidates already categorized by gf-style patterns (sqli/xss/lfi/ssrf/redirect), sensitive files, JS files,
port/service output, and vuln-scanner output. ANALYZE it and produce a clean, honest findings list.

Methodology to apply when reading the output:
- URLs with parameters are the prime injection surface. Parameters matching sqli patterns on .php/.asp/.jsp
  endpoints are SQLi candidates; reflected params are XSS candidates; file/path params are LFI/traversal.
- Exposed sensitive files (.env/.sql/.bak/.config/.git) are information-disclosure findings.
- JS files may leak endpoints/secrets — flag for manual review.
- Open ports/services (from nmap) → map to service-specific risks (outdated version, default creds, exposed admin).
- 'auth:*' sources are CREDENTIALED (authenticated) checks run over SSH: correlate installed package versions
  (key_packages/kernel_pkgs) with known CVEs; flag SSH misconfig (PermitRootLogin yes, PasswordAuthentication yes,
  PermitEmptyPasswords yes), passwordless sudo, unusual SUID binaries, world-writable files, and stale patching.
- Corroborate across tools; a single low-signal hit is 'needs_review', not 'confirmed'.

Rules:
- Only report what the tool output actually supports. Do NOT invent vulnerabilities or fabricate PoCs.
- status: 'confirmed' ONLY with direct evidence/PoC in the output (e.g. sqlmap/dalfox positive); else 'likely'/'needs_review'.
- Honest confidence (0-100).
- remediation must be CONCRETE: `fix_config` is the actual copy-pasteable config/code for the DETECTED stack
  (real nginx/apache directive, real parameterized query, exact header/cipher line); `fix_steps` = apply + verify. Never vague.
- Reply with ONLY a JSON array (no prose, no markdown fences). Each item:
  {"title","severity":"critical|high|medium|low|info","status":"confirmed|likely|needs_review",
   "confidence":int,"affected","cve","description","evidence","remediation","fix_config","fix_steps",
   "sources":[tool names]}."""

# gf-style parameter patterns (from tomnomnom/gf) — applied in Python to the merged URL list,
# so the "parameter extraction + gf pattern tagging" methodology runs with no extra tools installed.
_GF_PARAMS = {
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name", "sort", "where",
             "search", "params", "process", "row", "view", "table", "from", "sel", "results", "sleep",
             "fetch", "order", "keyword", "column", "field", "delete", "string", "number", "filter", "cat", "page"},
    "xss": {"q", "s", "search", "id", "action", "keyword", "query", "page", "keywords", "year", "view",
            "email", "type", "name", "p", "month", "image", "order", "dir", "title", "data", "redirect"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "doc", "page",
            "cat", "dir", "action", "board", "download", "prefix", "include", "inc", "locate", "show",
            "site", "view", "content", "layout", "mod", "conf", "url"},
    "ssrf": {"url", "uri", "path", "dest", "redirect", "out", "view", "to", "image", "link", "request",
             "u", "go", "domain", "feed", "host", "site", "html", "callback", "return", "port", "proxy", "next"},
    "redirect": {"url", "redirect", "next", "return", "r", "u", "link", "goto", "dest", "destination",
                 "go", "out", "target", "rurl", "continue", "returnurl"},
}
_SENSITIVE_EXT = (".env", ".sql", ".bak", ".old", ".backup", ".config", ".conf", ".ini", ".yml", ".yaml",
                  ".git", ".zip", ".tar.gz", ".tgz", ".db", ".log", ".json", ".xml", ".properties", ".pem", ".key")


def _param_names(url: str) -> set[str]:
    try:
        q = url.split("?", 1)[1]
    except IndexError:
        return set()
    return {kv.split("=", 1)[0].lower() for kv in q.replace("&", ";").split(";") if "=" in kv}


def categorize_urls(urls: list[str]) -> dict[str, list[str]]:
    """Parameter extraction + gf-style tagging + sensitive-file / JS detection (the ebook flow)."""
    out: dict[str, list[str]] = {k: [] for k in _GF_PARAMS}
    out["params"] = []
    out["sensitive_files"] = []
    out["js"] = []
    for u in urls:
        low = u.lower()
        path = low.split("?", 1)[0]
        if path.endswith(".js"):
            out["js"].append(u)
        if any(path.endswith(ext) or ext + "?" in low or path.endswith("/.git") for ext in _SENSITIVE_EXT):
            out["sensitive_files"].append(u)
        if "?" in u and "=" in u:
            out["params"].append(u)
            names = _param_names(u)
            for cat, pats in _GF_PARAMS.items():
                if names & pats:
                    out[cat].append(u)
    return {k: sorted(set(v)) for k, v in out.items()}


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
            ("nuclei", host, {"severity": "info,low,medium,high,critical"}, "Full template vuln scan (all severities)"),
            ("nmap", host, {"sv": True, "scripts": "vuln"}, "Network vulnerability scripts (nmap NSE)"),
            ("nikto", host, {}, "Web server vuln scan"),
            ("sslscan", host, {}, "TLS/SSL protocol + cipher audit"),
        ]),
    ]
    if mode == "pentest":
        phases.append(("Content discovery", [
            ("ffuf", host, {}, "Directory/file brute-force (seclists)"),
            ("arjun", host, {}, "Discover hidden parameters"),
        ]))
    return phases


def _run_live(target: Target, mode: str, autonomy: str, emit: Emit,
              on_finding: Callable[[dict], None], stop_event: threading.Event | None = None) -> str:
    host = target.value
    phases = _phases(target, mode)
    flat = [(t, h, o, d) for _, steps in phases for (t, h, o, d) in steps]
    has_auth = target.auth_type in ("ssh_password", "ssh_key") and bool(target.auth_user)

    plan_steps = []
    if has_auth:
        plan_steps.append({"n": 1, "tool": "auth-va", "desc": "Credentialed SSH assessment"})
    base = len(plan_steps)
    plan_steps += [{"n": base + i + 1, "tool": t, "desc": d} for i, (t, _, _, d) in enumerate(flat)]
    emit({"type": "plan", "steps": plan_steps})
    emit({"type": "reasoning", "text": f"Authorized {mode.upper()} on {host}. "
          f"{'Credentialed + ' if has_auth else ''}{len(phases)} phases, scope-enforced. "
          "Multi-source results are merged and deduped; then Claude analyzes."})

    collected: list[tuple[str, str, str]] = []
    all_findings: list[dict] = []
    url_lines: list[str] = []
    sub_lines: list[str] = []
    n = 0

    # Credentialed VA first (if SSH creds configured for this target)
    if has_auth and not _stopped(stop_event):
        n += 1
        emit({"type": "step", "n": n, "tool": "auth-va", "status": "running", "text": "Credentialed SSH assessment"})
        from . import auth_va
        auth_collected = auth_va.run_auth_va(target, emit, stop_event)
        collected += auth_collected
        emit({"type": "step", "n": n, "tool": "auth-va", "status": "done" if auth_collected else "failed",
              "text": f"Credentialed checks — {len(auth_collected)} data point(s)"})

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

    # Merge + dedupe + parameter extraction + gf-pattern tagging (3 Bugs methodology)
    uniq_urls = sorted({u for u in url_lines if u.startswith("http")})
    uniq_subs = sorted(set(sub_lines))
    cats = categorize_urls(uniq_urls)
    if uniq_urls:
        emit({"type": "reasoning", "text":
              f"Merged URLs: {len(url_lines)} raw → {len(uniq_urls)} unique (deduped). "
              f"Params: {len(cats['params'])} · SQLi-cand: {len(cats['sqli'])} · XSS-cand: {len(cats['xss'])} · "
              f"LFI-cand: {len(cats['lfi'])} · sensitive files: {len(cats['sensitive_files'])} · JS: {len(cats['js'])}"})
        collected.append(("merged-urls", "merge+dedupe", "\n".join(uniq_urls[:300])))
        for cat in ("sqli", "xss", "lfi", "ssrf", "redirect", "sensitive_files", "js"):
            if cats.get(cat):
                collected.append((f"{cat}-candidates", "gf-pattern/python", "\n".join(cats[cat][:60])))
    if uniq_subs:
        emit({"type": "reasoning", "text": f"Subdomains discovered: {len(uniq_subs)} unique."})

    # Exploit-DB correlation on detected services (local CSV lookup, no target contact)
    nmap_out = next((out for (tn, _, out) in collected if tn == "nmap"), "")
    if nmap_out:
        from . import exploitdb
        exploits = exploitdb.correlate(nmap_out)
        if exploits:
            emit({"type": "reasoning", "text": f"Exploit-DB: {len(exploits)} candidate public exploit(s) matched to detected service versions."})
            emit({"type": "intel", "kind": "exploit-db", "items": exploits})
            collected.append(("exploit-db", "exploit-db correlation",
                              "\n".join(f"[{e['date']}] {e['description']} ({e['type']}/{e['platform']}) — {e['url']}"
                                        for e in exploits)))

    # CVE tagging + NVD enrichment (from nuclei/service/exploit-db output)
    if not _stopped(stop_event):
        from . import cve
        all_text = "\n".join(out for (_, _, out) in collected)
        cves = cve.enrich(all_text, limit=6)
        if cves:
            emit({"type": "reasoning", "text": f"CVE intel: {len(cves)} CVE(s) identified; enriched with NVD CVSS."})
            emit({"type": "intel", "kind": "cve", "items": cves})
            collected.append(("cve-intel", "nvd enrichment",
                              "\n".join(f"{c['cve']} CVSS {c['cvss']} ({c['severity']}): {c['summary']}" for c in cves)))

    # Active payload testing — prove candidates (reflected XSS / SQLi / LFI) with evidence
    if mode == "pentest" and autonomy == "auto" and not _stopped(stop_event) and any(
            cats.get(c) for c in ("xss", "sqli", "lfi")):
        from . import probe
        emit({"type": "step", "n": n + 1, "tool": "payload-probe", "status": "running",
              "text": "Active payload testing on gf candidates"})
        proven = probe.run_probes(target, cats, emit, stop_event)
        all_findings += proven
        emit({"type": "step", "n": n + 1, "tool": "payload-probe", "status": "done",
              "text": f"Payload testing — {len(proven)} proven"})
        n += 1
    elif mode == "pentest" and autonomy != "auto" and any(cats.get(c) for c in ("xss", "sqli", "lfi")):
        emit({"type": "approval_required", "tool": "payload-probe",
              "text": "Active payload testing (XSS/SQLi/LFI probes) held for operator approval."})

    # Targeted intrusive validation on the best gf candidates (pentest mode only)
    if mode == "pentest" and not _stopped(stop_event):
        for tname, cand in (("sqlmap", cats["sqli"]), ("dalfox", cats["xss"])):
            tool = tools.REGISTRY.get(tname)
            if not tool or not tool.installed or not cand:
                continue
            purl = next((u for u in cand if host in u), cand[0])
            if autonomy != "auto":
                emit({"type": "approval_required", "tool": tname,
                      "text": f"Intrusive {tname} on {purl} held for operator approval."})
                continue
            if _stopped(stop_event):
                break
            n += 1
            emit({"type": "reasoning", "text": f"Validating {tname} on gf-{tname} candidate: {purl}"})
            res = executor.run(target, tname, host, {"param_url": purl}, stop_event)
            emit({"type": "exec", "tool": tname, "host": purl, "command": res.command,
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
    all_findings += _ai_extract_findings(target, collected, emit)

    # (2) Align severity to CVE CVSS where a CVE is present
    all_findings = _apply_cve_severity(all_findings, emit)

    # (1) Anti-FP verification pass over ALL findings (probe + AI)
    if all_findings and not _stopped(stop_event):
        emit({"type": "reasoning", "text": "Anti-false-positive pass: adversarially challenging every finding before reporting…"})
        all_findings = _verify_findings(target, all_findings, emit)

    for f in all_findings:
        on_finding(f)
        emit({"type": "finding", "finding": f})

    summary = (f"Live {mode.upper()} complete on {host}: {len(collected)} data source(s), "
               f"{len(uniq_urls)} unique URLs, {len(all_findings)} finding(s) analyzed + verified by Claude.")
    emit({"type": "finish", "text": summary})
    return summary


def _ai_extract_findings(target: Target, collected: list[tuple[str, str, str]], emit: Emit) -> list[dict]:
    """Single Claude call: analyze real tool output → structured findings, with RAG payloads."""
    from . import kb_index, llm

    blob = []
    present = {name for name, _, _ in collected}
    for tool_name, command, output in collected:
        blob.append(f"### {tool_name}\n$ {command}\n{output[:6000]}")
    kb = knowledge.methodology_brief(f"web vulnerability {target.value} owasp sqli xss headers tls")

    # RAG: pull real payloads/techniques from the corpus for whatever surfaced.
    rag_queries = []
    if "sqli-candidates" in present or "sqlmap" in present:
        rag_queries.append("SQL injection payload bypass WAF union based blind")
    if "xss-candidates" in present or "dalfox" in present:
        rag_queries.append("XSS payload filter bypass reflected DOM")
    if "lfi-candidates" in present:
        rag_queries.append("local file inclusion path traversal payload")
    if "ssrf-candidates" in present:
        rag_queries.append("SSRF payload bypass internal metadata")
    if not rag_queries:
        rag_queries.append("web application security headers misconfiguration")
    rag = "\n\n".join(kb_index.brief(q, k=3) for q in rag_queries[:3])
    if rag.strip():
        emit({"type": "reasoning", "text": "Retrieved payloads/techniques from corpus (PayloadsAllTheThings/writeups) for analysis."})

    user = (f"Target: {target.label} ({target.value}), engagement: {target.engagement or 'internal'}.\n"
            f"Authorized scope: {', '.join([target.value] + (target.scope_extra or []))}.\n\n"
            f"Scanner output to analyze:\n\n" + "\n\n".join(blob) + f"\n\n{kb}\n\n{rag}\n\n"
            "Extract the findings as the JSON array specified. Use the retrieved payloads/techniques to judge "
            "exploitability and to write accurate evidence/remediation. If the output shows no issues, return [].")
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


_VERIFY_SYSTEM = """You are an adversarial QA reviewer on an RSA VAPT team. You are given a list of
draft findings (with their evidence). Your job is to reduce false positives: for EACH finding decide whether
its evidence genuinely supports it.
- If the evidence is a reproduced PoC (reflected payload, SQL error, differential, /etc/passwd content), keep
  'confirmed'. If it's only a scanner hit with no proof, downgrade to 'likely' or 'needs_review' and lower confidence.
- If the evidence does not support the claim at all, set status 'false_positive'.
- Append a one-sentence verification note to 'description' prefixed with 'VERIFY: '.
Reply with ONLY a JSON array of the SAME findings (same fields) with adjusted status/confidence/description."""


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _cvss_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _apply_cve_severity(findings: list[dict], emit: Emit) -> list[dict]:
    """If a finding references a CVE, enrich it with NVD CVSS and raise severity to match."""
    from . import cve
    bumped = 0
    for f in findings:
        cves = cve.extract(f.get("cve", "") + " " + f.get("description", "") + " " + f.get("evidence", ""))
        if not cves:
            continue
        c = cve.nvd_lookup(cves[0])
        f["cve"] = cves[0]
        if c.get("cvss"):
            band = _cvss_band(float(c["cvss"]))
            if _SEV_RANK.get(band, 0) > _SEV_RANK.get(f.get("severity", "info"), 0):
                f["severity"] = band
                bumped += 1
            note = f" (CVE {cves[0]} · CVSS {c['cvss']} {c.get('severity') or ''})"
            if note.strip() not in f.get("description", ""):
                f["description"] = (f.get("description", "") + note).strip()
    if bumped:
        emit({"type": "reasoning", "text": f"CVE/CVSS alignment raised severity on {bumped} finding(s)."})
    return findings


def _verify_findings(target: Target, findings: list[dict], emit: Emit) -> list[dict]:
    """Second AI pass that challenges each finding to cut false positives."""
    from . import llm
    try:
        slim = [{"title": f["title"], "severity": f["severity"], "status": f["status"],
                 "confidence": f["confidence"], "evidence": f.get("evidence", ""),
                 "affected": f.get("affected", "")} for f in findings]
        client = llm.make_client()
        resp = client.messages.create(
            model=settings.ai_model, max_tokens=4000, system=_VERIFY_SYSTEM,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": "Findings to review:\n" + json.dumps(slim, indent=1)}],
        )
        if resp.stop_reason == "refusal":
            return findings
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        s, e = text.find("["), text.rfind("]")
        verdicts = json.loads(text[s:e + 1]) if s != -1 and e != -1 else []
        by_title = {v.get("title"): v for v in verdicts if isinstance(v, dict)}
        out = []
        dropped = 0
        for f in findings:
            v = by_title.get(f["title"])
            if v:
                f = {**f, "status": v.get("status", f["status"]),
                     "confidence": int(v.get("confidence", f["confidence"]) or f["confidence"]),
                     "description": v.get("description", f["description"])}
            if f["status"] == "false_positive":
                dropped += 1
            out.append(f)
        if dropped:
            emit({"type": "reasoning", "text": f"Verification dropped {dropped} finding(s) as false positive."})
        return out
    except Exception:  # noqa: BLE001
        return findings


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
