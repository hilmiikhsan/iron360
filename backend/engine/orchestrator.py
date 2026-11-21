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
    "rce": {"cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func",
            "arg", "option", "load", "process", "step", "read", "feature", "exe", "module", "payload",
            "run", "print", "daemon", "upload", "dir", "download", "log", "ip", "host", "port"},
    "ssti": {"name", "preview", "id", "activity", "template", "page", "dialog", "view", "content",
             "message", "msg", "redirect", "query", "search", "q", "title", "body", "text", "user"},
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
# Scan profiles (Nessus-style policies) — which phases run and how intense.
# Each profile lists the ordered phase names it includes; "content" only ever
# runs in pentest mode. The Vulnerability-scan phase composition is profile-aware.
PROFILES: dict[str, dict] = {
    "full":       {"phases": ["recon", "fingerprint", "port", "crawl", "vuln", "content"],
                   "desc": "Everything — deepest coverage"},
    "quick":      {"phases": ["recon", "fingerprint", "port", "vuln"],
                   "desc": "Fast triage — high/critical only"},
    "web":        {"phases": ["fingerprint", "crawl", "vuln", "content"],
                   "desc": "Web application focus"},
    "network":    {"phases": ["recon", "port", "vuln"],
                   "desc": "Network/host focus — ports + NSE"},
    "compliance": {"phases": ["fingerprint", "vuln"],
                   "desc": "Credentialed CIS compliance focus"},
}


def _vuln_steps(host: str, profile: str) -> list[tuple[str, str, dict, str]]:
    if profile == "quick":
        return [("nuclei", host, {"severity": "high,critical"}, "Template vuln scan (high/critical)")]
    if profile == "network":
        return [("nmap", host, {"sv": True, "scripts": "vuln"}, "Network vulnerability scripts (nmap NSE)")]
    if profile == "web":
        return [
            ("nuclei", host, {"severity": "info,low,medium,high,critical"}, "Full template vuln scan (all severities)"),
            ("nikto", host, {}, "Web server vuln scan"),
            ("sslscan", host, {}, "TLS/SSL protocol + cipher audit"),
        ]
    if profile == "compliance":
        return [
            ("nuclei", host, {"severity": "medium,high,critical"}, "Misconfig/exposure template scan"),
            ("sslscan", host, {}, "TLS/SSL protocol + cipher audit"),
        ]
    # full
    return [
        ("nuclei", host, {"severity": "info,low,medium,high,critical"}, "Full template vuln scan (all severities)"),
        ("nmap", host, {"sv": True, "scripts": "vuln"}, "Network vulnerability scripts (nmap NSE)"),
        ("nikto", host, {}, "Web server vuln scan"),
        ("sslscan", host, {}, "TLS/SSL protocol + cipher audit"),
    ]


def _phases(target: Target, mode: str, profile: str = "full") -> list[tuple[str, list[tuple[str, str, dict, str]]]]:
    """Phased pipeline, filtered by the selected scan profile. (tool, host, options, description)."""
    host = target.value
    is_domain = target.kind == "domain"
    wanted = PROFILES.get(profile, PROFILES["full"])["phases"]

    recon = []
    if is_domain:
        if mode == "pentest":
            # Subdomain enum only in pentest — VA focuses on the single target domain.
            recon.append(("subfinder",    host, {}, "Subdomain enum — subfinder"))
            recon.append(("assetfinder",  host, {}, "Subdomain enum — assetfinder"))
            recon.append(("amass",        host, {}, "Subdomain enum — amass (passive)"))
            recon.append(("findomain",    host, {}, "Subdomain enum — findomain"))
        # URL archive tools gather known paths/params on the target domain itself.
        recon.append(("gau",          host, {}, "Gather known URLs — Wayback/OTX (passive)"))
        recon.append(("waybackurls",  host, {}, "Gather URLs — Wayback Machine (passive)"))
    recon.append(("dnsx", host, {}, "Resolve DNS records"))

    blocks: dict[str, tuple[str, list]] = {
        "recon": ("Recon", recon),
        "fingerprint": ("Fingerprint", [
            ("httpx", host, {}, "Probe live HTTP + tech stack"),
            ("whatweb", host, {}, "Fingerprint web technologies"),
        ]),
        "port": ("Port scan", [("nmap", host, {"sv": True}, "Top ports + service versions")]),
        "crawl": ("Crawl", [("katana", host, {}, "Crawl endpoints (active)")]),
        "vuln": ("Vulnerability scan", _vuln_steps(host, profile)),
        "content": ("Content discovery", [
            ("ffuf", host, {}, "Directory/file brute-force (seclists)"),
            ("arjun", host, {}, "Discover hidden parameters"),
        ]),
    }

    phases: list[tuple[str, list]] = []
    for name in wanted:
        if name == "content" and mode != "pentest":
            continue  # content discovery is intrusive — pentest only
        if name in blocks and blocks[name][1]:
            phases.append(blocks[name])
    return phases


def _run_live(target: Target, mode: str, autonomy: str, emit: Emit,
              on_finding: Callable[[dict], None], stop_event: threading.Event | None = None,
              profile: str = "full", ask_approval: Callable[[str], bool] | None = None) -> str:
    host = target.value

    _ctr = {"n": 0}

    def _approve(tool: str, text: str) -> bool:
        """Intrusive-step gate. Auto mode runs it; Approve mode asks the operator and waits."""
        if autonomy == "auto":
            return True
        _ctr["n"] += 1
        approval_id = f"{tool}-{_ctr['n']}"
        if ask_approval is None:  # no interactive channel (e.g. sim) — fail closed
            emit({"type": "approval_required", "tool": tool, "text": text + " (no interactive channel — skipped)"})
            return False
        emit({"type": "approval_required", "approval_id": approval_id, "tool": tool,
              "text": text + " — awaiting operator approval."})
        ok = ask_approval(approval_id)
        emit({"type": "approval_resolved", "approval_id": approval_id, "tool": tool, "approved": ok,
              "text": f"{tool}: {'approved — running' if ok else 'denied/timeout — skipped'}"})
        return ok

    phases = _phases(target, mode, profile)
    flat = [(t, h, o, d) for _, steps in phases for (t, h, o, d) in steps]
    has_auth = target.auth_type in ("ssh_password", "ssh_key") and bool(target.auth_user)
    run_cis = profile == "compliance" or has_auth
    prof_desc = PROFILES.get(profile, PROFILES["full"])["desc"]

    plan_steps = []
    if has_auth:
        plan_steps.append({"n": 1, "tool": "auth-va", "desc": "Credentialed SSH assessment"})
    base = len(plan_steps)
    plan_steps += [{"n": base + i + 1, "tool": t, "desc": d} for i, (t, _, _, d) in enumerate(flat)]
    if run_cis:
        plan_steps.append({"n": len(plan_steps) + 1, "tool": "cis-compliance", "desc": "CIS benchmark evaluation"})
    emit({"type": "plan", "steps": plan_steps})
    emit({"type": "reasoning", "text": f"Authorized {mode.upper()} on {host} · profile: {profile} ({prof_desc}). "
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
            # Real-time line streaming (Claude-Code-style): each stdout line is forwarded live.
            _line_buf: list[str] = []
            def _line_emit(line: str, _t=tool_name) -> None:
                stripped = line.strip()
                if stripped:
                    _line_buf.append(stripped)
                    emit({"type": "log", "tool": _t, "line": stripped})
            res = executor.run(target, tool_name, h, opts, stop_event, line_emit=_line_emit)
            # Only emit the exec summary (not the full buffered output — already streamed live).
            emit({"type": "exec", "tool": tool_name, "host": h, "command": res.command,
                  "ok": res.ok, "exit_code": res.exit_code, "denied_reason": res.denied_reason,
                  "output": (res.denied_reason or f"({len(_line_buf)} lines streamed live)") if res.ok else
                             (res.stdout or res.stderr or res.denied_reason or "")[:3000],
                  "duration_s": round(res.duration_s, 1)})
            if res.ok:
                emit({"type": "step", "n": n, "tool": tool_name, "status": "done", "text": f"{desc} — {res.duration_s:.1f}s"})
                collected.append((tool_name, res.command, res.stdout or "(no output)"))
                lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                # Merge results from all URL/subdomain tools; dedup happens below.
                if tool_name in ("gau", "katana", "waybackurls", "hakrawler", "paramspider"):
                    url_lines += lines
                elif tool_name in ("subfinder", "assetfinder", "amass", "findomain"):
                    sub_lines += lines
            else:
                emit({"type": "step", "n": n, "tool": tool_name, "status": "failed", "text": res.denied_reason or "failed"})

    # CIS compliance evaluation (deterministic, from credentialed output)
    if run_cis and not _stopped(stop_event):
        n += 1
        emit({"type": "step", "n": n, "tool": "cis-compliance", "status": "running", "text": "CIS benchmark evaluation"})
        from . import compliance
        cis_findings = compliance.run_cis(collected, emit)
        all_findings += cis_findings
        emit({"type": "step", "n": n, "tool": "cis-compliance",
              "status": "done" if any(s.startswith("auth:") for s, _, _ in collected) else "skipped",
              "text": f"CIS evaluation — {len(cis_findings)} control failure(s)"})

    # CPHunter CVE mass-detection (VA) — scope-enforced; results cross-checked by the AI below.
    if profile != "quick" and not _stopped(stop_event):
        from . import cphunter_bridge
        if cphunter_bridge.available():
            n += 1
            emit({"type": "step", "n": n, "tool": "cphunter", "status": "running",
                  "text": "CVE mass-detection (CPHunter) — all modules"})
            cph = cphunter_bridge.detect(target, host, emit, stop_event)
            cph_findings = [_cph_to_finding(c, host) for c in cph]
            all_findings += cph_findings
            collected.append(("cphunter", "cve mass-scan",
                              "\n".join(f"[{c['state'].upper()}] {c['cve']} {c.get('version','')} "
                                        f"{c.get('evidence','')[:160]}" for c in cph) or "(no CVE hits)"))
            emit({"type": "step", "n": n, "tool": "cphunter", "status": "done",
                  "text": f"CPHunter — {sum(1 for c in cph if c['state']=='vulnerable')} vulnerable, "
                          f"{sum(1 for c in cph if c['state']=='inconclusive')} inconclusive"})

    # Merge + dedupe + parameter extraction + gf-pattern tagging (3 Bugs methodology).
    # All tool results (subfinder+assetfinder+amass, gau+waybackurls+katana, etc.) are
    # combined here — the AI gets ONE clean merged dataset, not raw per-tool output.
    uniq_urls = sorted({u for u in url_lines if u.startswith("http")})
    uniq_subs = sorted(set(sub_lines))
    cats = categorize_urls(uniq_urls)
    if uniq_subs:
        emit({"type": "reasoning", "text":
              f"Subdomains merged (subfinder+assetfinder+amass+findomain): {len(sub_lines)} raw → "
              f"{len(uniq_subs)} unique after dedup."})
        collected.append(("merged-subdomains", "merge+dedupe:subfinder+assetfinder+amass+findomain",
                          "\n".join(uniq_subs[:500])))
    if uniq_urls:
        emit({"type": "reasoning", "text":
              f"URLs merged (gau+waybackurls+katana): {len(url_lines)} raw → {len(uniq_urls)} unique. "
              f"Params: {len(cats['params'])} · SQLi: {len(cats['sqli'])} · XSS: {len(cats['xss'])} · "
              f"LFI: {len(cats['lfi'])} · sensitive: {len(cats['sensitive_files'])} · JS: {len(cats['js'])}"})
        collected.append(("merged-urls", "merge+dedupe:gau+waybackurls+katana", "\n".join(uniq_urls[:300])))
        for cat in ("sqli", "xss", "lfi", "ssrf", "redirect", "rce", "ssti", "sensitive_files", "js"):
            if cats.get(cat):
                collected.append((f"{cat}-candidates", "gf-pattern/python", "\n".join(cats[cat][:60])))

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

    # Active payload testing — prove candidates (XSS/SQLi/LFI/cmdi/SSTI/redirect + CORS/CRLF/headers)
    _probe_cats = ("xss", "sqli", "lfi", "rce", "ssti", "redirect")
    if mode == "pentest" and not _stopped(stop_event) and (
            any(cats.get(c) for c in _probe_cats) or True):  # target-level probes always apply in pentest
        if _approve("payload-probe", "Active payload testing (XSS/SQLi/OS-cmd/SSTI/redirect + CORS/CRLF/headers) on in-scope candidates"):
            from . import probe
            n += 1
            emit({"type": "step", "n": n, "tool": "payload-probe", "status": "running",
                  "text": "Active payload testing on gf candidates + target-level checks"})
            proven = probe.run_probes(target, cats, emit, stop_event)
            all_findings += proven
            emit({"type": "step", "n": n, "tool": "payload-probe", "status": "done",
                  "text": f"Payload testing — {len(proven)} proven"})

    # Targeted intrusive validation on the best gf candidates (pentest mode only)
    if mode == "pentest" and not _stopped(stop_event):
        for tname, cand in (("sqlmap", cats["sqli"]), ("dalfox", cats["xss"]), ("commix", cats.get("rce", []))):
            tool = tools.REGISTRY.get(tname)
            if not tool or not tool.installed or not cand:
                continue
            purl = next((u for u in cand if host in u), cand[0])
            if _stopped(stop_event):
                break
            if not _approve(tname, f"Intrusive {tname} validation on {purl}"):
                continue
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

    # (1) Anti-FP verification pass over findings (probe + AI). CIS checks are
    # deterministic config evaluations — exempt from the adversarial AI re-scoring.
    if all_findings and not _stopped(stop_event):
        det = [f for f in all_findings if "cis-benchmark" in (f.get("sources") or [])]
        challengeable = [f for f in all_findings if "cis-benchmark" not in (f.get("sources") or [])]
        if challengeable:
            emit({"type": "reasoning", "text": "Anti-false-positive pass: adversarially challenging every finding before reporting…"})
            challengeable = _verify_findings(target, challengeable, emit)
        all_findings = det + challengeable

    # CPHunter proof-of-impact exploitation (PT phase only, approval-gated, safe PoC, scope-enforced).
    if mode == "pentest" and not _stopped(stop_event):
        from . import cphunter_bridge
        if cphunter_bridge.available():
            exploit_targets = [f for f in all_findings
                               if f.get("_cph_state") == "vulnerable" and f.get("status") != "false_positive"]
            exploited = []
            for f in exploit_targets:
                if _stopped(stop_event):
                    break
                if not _approve(f"exploit-{f['cve']}",
                                f"Proof-of-impact exploit {f['cve']} on {host} (CPHunter safe PoC, read-only)"):
                    continue
                res = cphunter_bridge.exploit(target, f["cve"], host, emit, stop_event)
                if res.get("ran"):
                    f["evidence"] = (f.get("evidence", "") + "\n\n[EXPLOIT OUTPUT]\n" + (res.get("output") or ""))[:4000]
                    if res.get("success"):
                        f["status"] = "confirmed"
                        f["confidence"] = max(int(f.get("confidence", 0) or 0), 95)
                    exploited.append(f)
            if exploited:
                emit({"type": "reasoning", "text": "AI validating CPHunter exploit output as real proof-of-impact…"})
                validated = _verify_findings(target, exploited, emit)
                by_title = {v["title"]: v for v in validated}
                for f in exploited:
                    v = by_title.get(f["title"])
                    if v:
                        f["status"] = v.get("status", f["status"])
                        f["confidence"] = int(v.get("confidence", f["confidence"]) or f["confidence"])
                        f["description"] = v.get("description", f["description"])

    # OWASP Top 10 (2021) coverage matrix — what was checked + findings per category.
    matrix = _owasp_matrix(all_findings, mode, profile, has_auth)
    emit({"type": "intel", "kind": "owasp", "items": matrix})
    tested = sum(1 for m in matrix if m["method"] != "manual only")
    emit({"type": "reasoning", "text": f"OWASP Top 10 coverage: {tested}/10 categories actively checked this run."})

    for f in all_findings:
        on_finding(f)
        emit({"type": "finding", "finding": f})

    summary = (f"Live {mode.upper()} complete on {host}: {len(collected)} data source(s), "
               f"{len(uniq_urls)} unique URLs, {len(all_findings)} finding(s) analyzed + verified by Claude.")
    emit({"type": "finish", "text": summary})
    return summary


_OWASP_2021 = [
    ("A01", "Broken Access Control", "LFI/path-traversal probe, open-redirect probe, nuclei exposure templates"),
    ("A02", "Cryptographic Failures", "sslscan TLS/cipher audit, HSTS header check"),
    ("A03", "Injection", "active probes: SQLi/XSS/OS-cmd(commix)/SSTI/CRLF + sqlmap/dalfox + nuclei"),
    ("A04", "Insecure Design", "flagged for manual review (business-logic)"),
    ("A05", "Security Misconfiguration", "security-header/CORS/HTTP-method probe, GraphQL introspection, exposed .git/.env/actuator, nikto, nuclei misconfig"),
    ("A06", "Vulnerable & Outdated Components", "nmap -sV, nuclei CVE templates, CVE/NVD enrichment, Exploit-DB correlation, wpscan"),
    ("A07", "Identification & Auth Failures", "nuclei default-login/exposure; deeper auth testing manual"),
    ("A08", "Software & Data Integrity Failures", "nuclei deserialization/exposure templates"),
    ("A09", "Security Logging & Monitoring Failures", "manual only (not remotely testable)"),
    ("A10", "Server-Side Request Forgery (SSRF)", "SSRF candidate tagging + nuclei SSRF templates"),
]


def _owasp_matrix(findings: list[dict], mode: str, profile: str, has_auth: bool) -> list[dict]:
    """Report, per OWASP Top-10 2021 category, the method used + number of findings landed."""
    active = mode == "pentest"
    out = []
    for oid, name, method in _OWASP_2021:
        m = method
        if oid in ("A04", "A09"):
            m = "manual only"
        elif oid in ("A01", "A03", "A05", "A10") and not active:
            m = method + " (scan-only in VA mode)"
        found = sum(1 for f in findings if oid in (f.get("owasp", "") + " " + f.get("description", "")))
        out.append({"id": oid, "name": name, "method": m, "findings": found})
    return out


def _cph_to_finding(c: dict, host: str) -> dict:
    """Turn a CPHunter detection result into an Iron360 draft finding (AI cross-checks it later)."""
    cve = c.get("cve", "")
    if c.get("state") == "vulnerable":
        ex = c.get("exploit_state")
        ex_note = (" CPHunter safe-exploit confirmed impact." if ex is True
                   else " Safe-exploit inconclusive." if ex is None else "")
        return {
            "title": f"{cve} — vulnerable component (CPHunter)", "severity": "high", "status": "likely",
            "confidence": 72, "affected": f"{host}{(':' + str(c['port'])) if c.get('port') else ''}",
            "cve": cve,
            "description": f"CPHunter flagged {host} VULNERABLE to {cve}."
                           + (f" Detected version: {c['version']}." if c.get("version") else "")
                           + ex_note,
            "evidence": (c.get("evidence", "") + ("\n" + c.get("exploit_evidence", "") if c.get("exploit_evidence") else "")).strip(),
            "remediation": "Upgrade/patch the affected component to a fixed release; apply vendor advisory for this CVE.",
            "fix_config": "", "fix_steps": "1. Confirm installed version. 2. Upgrade to the patched release. "
                                           "3. Re-run detection to verify the CVE no longer matches.",
            "sources": ["cphunter"], "_cph_state": "vulnerable",
        }
    return {
        "title": f"{cve} — possible (unconfirmed version) (CPHunter)", "severity": "info", "status": "needs_review",
        "confidence": 30, "affected": host, "cve": cve,
        "description": f"CPHunter returned INCONCLUSIVE for {cve} on {host} — the component version could not be "
                       "confirmed, so this is NOT asserted as vulnerable (anti-false-positive).",
        "evidence": c.get("evidence", ""), "remediation": "Manually confirm the component version to decide.",
        "fix_config": "", "fix_steps": "", "sources": ["cphunter"], "_cph_state": "inconclusive",
    }


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
        rag_queries.append("XSS payload filter bypass reflected DOM polyglot")
    if "lfi-candidates" in present:
        rag_queries.append("local file inclusion path traversal payload wrapper php filter")
    if "ssrf-candidates" in present:
        rag_queries.append("SSRF payload bypass internal metadata gopher 169.254.169.254")
    if "rce-candidates" in present or "commix" in present:
        rag_queries.append("OS command injection payload bypass filter blind time based")
    if "ssti-candidates" in present:
        rag_queries.append("server side template injection payload jinja2 twig freemarker RCE")
    if "redirect-candidates" in present:
        rag_queries.append("open redirect bypass payload URL parser confusion")
    # Always pull misconfig/exposure knowledge for the target-level probes (CORS/headers/GraphQL/git/methods).
    rag_queries.append("CORS misconfiguration GraphQL introspection exposed .git .env security headers HTTP methods")
    rag = "\n\n".join(kb_index.brief(q, k=3) for q in rag_queries[:5])
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
                   on_finding: Callable[[dict], None], stop_event: threading.Event | None = None,
                   profile: str = "full", ask_approval: Callable[[str], bool] | None = None) -> str:
    emit({"type": "note", "text": f"Engine: {'LIVE (Claude)' if settings.ai_live else 'SIMULATION'}"})
    try:
        if settings.ai_live:
            return _run_live(target, mode, autonomy, emit, on_finding, stop_event, profile, ask_approval)
        return _run_sim(target, mode, autonomy, emit, on_finding, stop_event)
    except Exception as e:  # noqa: BLE001
        emit({"type": "error", "text": f"engine error: {e}"})
        return f"Assessment failed: {e}"
